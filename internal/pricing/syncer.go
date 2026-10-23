package pricing

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HTTPFetcher abstracts HTTP GET fetching so the syncer can use either the Host Callback (`host.http.do`)
// or Go's standard `http.Client`.
type HTTPFetcher func(ctx context.Context, url string, timeout time.Duration) ([]byte, error)

// LoggerFunc logs messages at ("info", "warn", "error") levels via the host callback or fallback logger.
type LoggerFunc func(level, message string, fields map[string]any)

// SyncConfig defines configuration for synchronizing models.dev pricing.
type SyncConfig struct {
	SyncURL      string
	CacheFile    string
	SyncInterval time.Duration
	HTTPTimeout  time.Duration
}

// Syncer runs background synchronization of models.dev pricing data with local disk caching and graceful fallback.
type Syncer struct {
	engine  *Engine
	fetcher HTTPFetcher
	logger  LoggerFunc

	mu          sync.Mutex
	cfg         SyncConfig
	cancel      context.CancelFunc
	initialDone chan struct{}
	stopped     chan struct{}
}

// NewSyncer creates a new models.dev background Syncer.
func NewSyncer(engine *Engine, fetcher HTTPFetcher, logger LoggerFunc) *Syncer {
	if fetcher == nil {
		fetcher = DefaultHTTPFetcher
	}
	if logger == nil {
		logger = func(string, string, map[string]any) {}
	}
	return &Syncer{
		engine:  engine,
		fetcher: fetcher,
		logger:  logger,
	}
}

// ConfigureAndStart loads local cache immediately (if available) and starts or restarts the background sync loop.
func (s *Syncer) ConfigureAndStart(cfg SyncConfig) {
	if strings.TrimSpace(cfg.SyncURL) == "" {
		cfg.SyncURL = "https://models.dev/api.json"
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 24 * time.Hour
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}

	s.Stop()

	s.mu.Lock()
	s.cfg = cfg
	// 1. Load local cache file on disk first so pricing is immediately ready even if offline
	if cfg.CacheFile != "" {
		if raw, err := os.ReadFile(cfg.CacheFile); err == nil && len(raw) > 0 {
			if count, errParse := s.engine.ParseAndLoadModelsDevJSON(raw, "models.dev(disk-cache)"); errParse == nil {
				s.logger("info", "loaded models.dev pricing cache from disk", map[string]any{
					"cache_file": cfg.CacheFile,
					"models":     count,
				})
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	initialDone := make(chan struct{})
	stopped := make(chan struct{})
	s.cancel = cancel
	s.initialDone = initialDone
	s.stopped = stopped
	s.mu.Unlock()

	go s.loop(ctx, cfg, initialDone, stopped)
}

// WaitInitialSync waits until the initial models.dev sync pass after ConfigureAndStart has completed.
func (s *Syncer) WaitInitialSync(timeout time.Duration) {
	s.mu.Lock()
	ch := s.initialDone
	s.mu.Unlock()
	if ch == nil {
		return
	}
	if timeout <= 0 {
		<-ch
		return
	}
	select {
	case <-ch:
	case <-time.After(timeout):
	}
}

// Stop halts the background sync goroutine cleanly.
func (s *Syncer) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	stopped := s.stopped
	s.cancel = nil
	s.initialDone = nil
	s.stopped = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
}

func (s *Syncer) loop(ctx context.Context, cfg SyncConfig, initialDone, stopped chan struct{}) {
	defer close(stopped)

	// Immediate initial sync on startup
	_, _ = s.SyncOnce(ctx)
	close(initialDone)

	ticker := time.NewTicker(cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.SyncOnce(ctx)
		}
	}
}

// SyncOnce fetches the latest models.dev JSON, updates the in-memory pricing table, and writes the local cache file.
// On network or parse error, it logs a Warn message and keeps existing cached/custom prices intact.
func (s *Syncer) SyncOnce(ctx context.Context) (int, error) {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	if strings.TrimSpace(cfg.SyncURL) == "" {
		return 0, fmt.Errorf("sync URL is empty")
	}

	raw, err := s.fetcher(ctx, cfg.SyncURL, cfg.HTTPTimeout)
	if err != nil {
		s.engine.RecordSyncError(err)
		s.logger("warn", "failed to fetch models.dev pricing; degrading gracefully to cached/custom prices", map[string]any{
			"url":   cfg.SyncURL,
			"error": err.Error(),
		})
		return 0, err
	}

	count, err := s.engine.ParseAndLoadModelsDevJSON(raw, "models.dev")
	if err != nil {
		s.engine.RecordSyncError(err)
		s.logger("warn", "failed to parse models.dev pricing JSON; degrading gracefully to cached/custom prices", map[string]any{
			"url":   cfg.SyncURL,
			"error": err.Error(),
		})
		return 0, err
	}

	if cfg.CacheFile != "" {
		if errWrite := writeFileAtomicallyWithRetry(cfg.CacheFile, raw); errWrite != nil {
			s.logger("warn", "failed to persist models.dev cache file", map[string]any{
				"cache_file": cfg.CacheFile,
				"error":      errWrite.Error(),
			})
		}
	}

	s.logger("info", "synchronized models.dev reference pricing", map[string]any{
		"models": count,
		"url":    cfg.SyncURL,
	})
	return count, nil
}

// DefaultHTTPFetcher fetches a URL using standard net/http with timeout.
func DefaultHTTPFetcher(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CLIProxyAPI-Plugin-KeyGuard/1.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected HTTP status %d from %s", resp.StatusCode, url)
	}
	// Limit read to 64MB for safety
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
}

// writeFileAtomicallyWithRetry writes data to a temporary file and renames it over path,
// with a lightweight retry loop (3 attempts, 20ms sleep) for Windows file handle lock resilience.
func writeFileAtomicallyWithRetry(targetPath string, data []byte) error {
	cleanPath := filepath.Clean(targetPath)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", cleanPath, time.Now().UnixNano())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		if err := os.Rename(tmpPath, cleanPath); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	_ = os.Remove(tmpPath)
	return lastErr
}
