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

	lifecycleMu sync.Mutex // serializes ConfigureAndStart and Stop
	mu          sync.Mutex
	epoch       uint64
	flight      *syncFlight
	cfg         SyncConfig
	cancel      context.CancelFunc
	initialDone chan struct{}
	stopped     chan struct{}
}

// syncFlight coalesces manual/background requests within one configuration epoch.
// Result fields are published by closing done.
type syncFlight struct {
	epoch  uint64
	done   chan struct{}
	cancel context.CancelFunc
	count  int
	err    error
}

const maxCatalogBytes = 64 * 1024 * 1024

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

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.stop()

	s.mu.Lock()
	// Invalidate manual work started while stop waited for the previous loop.
	s.epoch++
	if s.flight != nil {
		s.flight.cancel()
		s.flight = nil
	}
	s.cfg = cfg
	// 1. Load local cache file on disk first so pricing is immediately ready even if offline
	if cfg.CacheFile != "" {
		if raw, err := readCatalogFile(cfg.CacheFile); err == nil && len(raw) > 0 {
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
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.stop()
}

func (s *Syncer) stop() {
	s.mu.Lock()
	s.epoch++
	if s.flight != nil {
		s.flight.cancel()
		s.flight = nil
	}
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

// SyncOnce joins an existing fetch for the current configuration, or performs one.
// The initiating caller owns the shared fetch context; a joining caller may stop
// waiting independently. Stop/reconfigure cancels and invalidates old flights, so
// even a fetcher ignoring cancellation cannot publish an obsolete catalog/cache.
func (s *Syncer) SyncOnce(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	if flight := s.flight; flight != nil && flight.epoch == s.epoch {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-flight.done:
			return flight.count, flight.err
		}
	}
	cfg := s.cfg
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	fetchCtx, cancel := context.WithTimeout(ctx, cfg.HTTPTimeout)
	flight := &syncFlight{epoch: s.epoch, done: make(chan struct{}), cancel: cancel}
	s.flight = flight
	s.mu.Unlock()

	count, err := s.fetchAndPublish(fetchCtx, cfg, flight.epoch)
	cancel()
	s.mu.Lock()
	flight.count, flight.err = count, err
	if s.flight == flight {
		s.flight = nil
	}
	close(flight.done)
	s.mu.Unlock()
	return count, err
}

func (s *Syncer) fetchAndPublish(ctx context.Context, cfg SyncConfig, epoch uint64) (int, error) {
	if strings.TrimSpace(cfg.SyncURL) == "" {
		return 0, fmt.Errorf("sync URL is empty")
	}
	raw, err := s.fetcher(ctx, cfg.SyncURL, cfg.HTTPTimeout)
	if err == nil && len(raw) > maxCatalogBytes {
		err = fmt.Errorf("models.dev catalog exceeds %d bytes", maxCatalogBytes)
	}
	// Configuration publication and cache replacement share the epoch lock. Old
	// work cannot modify either after a reconfiguration or Stop has invalidated it.
	s.mu.Lock()
	if epoch != s.epoch || ctx.Err() != nil {
		s.mu.Unlock()
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, context.Canceled
	}
	if err == nil {
		var count int
		count, err = s.engine.ParseAndLoadModelsDevJSON(raw, "models.dev")
		if err == nil {
			if cfg.CacheFile != "" {
				if errWrite := writeFileAtomicallyWithRetry(cfg.CacheFile, raw); errWrite != nil {
					err = fmt.Errorf("prices updated in memory but cache persistence failed: %w", errWrite)
				}
			}
			if err != nil {
				s.engine.RecordSyncError(err)
			}
			s.mu.Unlock()
			if err != nil {
				s.logger("warn", "failed to persist models.dev cache", map[string]any{"error": err.Error()})
				return count, err
			}
			s.logger("info", "synchronized models.dev reference pricing", map[string]any{"models": count, "url": cfg.SyncURL})
			return count, nil
		}
	}
	s.engine.RecordSyncError(err)
	s.mu.Unlock()
	s.logger("warn", "failed to synchronize models.dev pricing; keeping existing prices", map[string]any{"url": cfg.SyncURL, "error": err.Error()})
	return 0, err
}

func readCatalogFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readCatalog(file)
}

func readCatalog(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxCatalogBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCatalogBytes {
		return nil, fmt.Errorf("models.dev catalog exceeds %d bytes", maxCatalogBytes)
	}
	return raw, nil
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
	return readCatalog(resp.Body)
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
