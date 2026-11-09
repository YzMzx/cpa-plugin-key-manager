package pricing

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// observingContext lets the test wait until a joining caller is selecting on
// cancellation, without sleeps or relying on goroutine scheduling order.
type observingContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestSyncOnceCoalescesConcurrentFetches(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	syncer := NewSyncer(NewEngine(), func(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
		calls.Add(1)
		close(entered)
		<-release
		return []byte(sampleModelsDevJSON), nil
	}, nil)
	syncer.cfg = SyncConfig{SyncURL: "https://example.invalid/prices", HTTPTimeout: time.Minute}
	first := make(chan error, 1)
	go func() { _, err := syncer.SyncOnce(context.Background()); first <- err }()
	<-entered
	joined := make(chan error, 1)
	ctx := &observingContext{Context: context.Background(), observed: make(chan struct{})}
	go func() { _, err := syncer.SyncOnce(ctx); joined <- err }()
	<-ctx.observed
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("fetch calls=%d want 1", calls.Load())
	}
}

func TestJoiningSyncCanCancelWithoutCancelingLeader(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	syncer := NewSyncer(NewEngine(), func(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
		close(entered)
		<-release
		return []byte(sampleModelsDevJSON), nil
	}, nil)
	syncer.cfg = SyncConfig{SyncURL: "https://example.invalid/prices", HTTPTimeout: time.Minute}
	first := make(chan error, 1)
	go func() { _, err := syncer.SyncOnce(context.Background()); first <- err }()
	<-entered
	base, cancel := context.WithCancel(context.Background())
	ctx := &observingContext{Context: base, observed: make(chan struct{})}
	joined := make(chan error, 1)
	go func() { _, err := syncer.SyncOnce(ctx); joined <- err }()
	<-ctx.observed
	cancel()
	if err := <-joined; !errors.Is(err, context.Canceled) {
		t.Fatalf("join error=%v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestOldManualSyncCannotOverwriteReconfiguredCatalogOrCache(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	engine := NewEngine()
	syncer := NewSyncer(engine, func(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
		if url == "old" {
			close(entered)
			<-release
			return []byte(sampleModelsDevJSON), nil
		}
		return []byte(`{"new":{"models":{"new-model":{"cost":{"input":7}}}}}`), nil
	}, nil)
	cache := filepath.Join(t.TempDir(), "prices.json")
	syncer.cfg = SyncConfig{SyncURL: "old", HTTPTimeout: time.Minute, CacheFile: cache}
	oldDone := make(chan error, 1)
	go func() { _, err := syncer.SyncOnce(context.Background()); oldDone <- err }()
	<-entered
	syncer.ConfigureAndStart(SyncConfig{SyncURL: "new", HTTPTimeout: time.Minute, SyncInterval: time.Hour, CacheFile: cache})
	defer syncer.Stop()
	syncer.WaitInitialSync(time.Second * 5)
	if price, ok := engine.Lookup("new-model"); !ok || price.Input != 7 {
		t.Fatalf("new config not loaded: %+v", price)
	}
	close(release)
	if err := <-oldDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("obsolete sync error=%v", err)
	}
	if _, ok := engine.Lookup("gpt-4o"); ok {
		t.Fatal("obsolete sync overwrote new catalog")
	}
	raw, err := os.ReadFile(cache)
	if err != nil || !strings.Contains(string(raw), "new-model") {
		t.Fatalf("cache overwritten or missing: %s (%v)", raw, err)
	}
}

func TestCachePersistenceFailureIsReported(t *testing.T) {
	engine := NewEngine()
	syncer := NewSyncer(engine, func(context.Context, string, time.Duration) ([]byte, error) { return []byte(sampleModelsDevJSON), nil }, nil)
	// A regular file cannot serve as the parent of the configured cache file.
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	syncer.cfg = SyncConfig{SyncURL: "test", HTTPTimeout: time.Minute, CacheFile: filepath.Join(parent, "cache.json")}
	count, err := syncer.SyncOnce(context.Background())
	if err == nil || count == 0 {
		t.Fatalf("want in-memory count and persist error, got %d,%v", count, err)
	}
	if _, ok := engine.Lookup("gpt-4o"); !ok {
		t.Fatal("valid in-memory catalog lost")
	}
	if engine.Status().LastSyncError == "" {
		t.Fatal("cache failure absent from status")
	}
}
