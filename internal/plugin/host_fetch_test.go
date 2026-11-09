package plugin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

func TestPriceFetchNeverCallsUncancellableHostHTTPAndRespectsDeadline(t *testing.T) {
	var invoked atomic.Int32
	bridge := NewHostBridge(func(method string, payload []byte) ([]byte, error) {
		if method == pluginabi.MethodHostHTTPDo {
			invoked.Add(1)
			t.Fatal("uncancellable host HTTP used")
		}
		return nil, nil
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := bridge.FetchURL(ctx, server.URL, time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not honored: %v", err)
	}
	if invoked.Load() != 0 {
		t.Fatal("host callback was invoked")
	}
}
func TestPriceFetchHTTPStatusAndCatalogSuccess(t *testing.T) {
	bridge := NewHostBridge(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"provider":{"models":{}}}`))
	}))
	defer server.Close()
	raw, err := bridge.FetchURL(context.Background(), server.URL, time.Second)
	if err != nil || len(raw) == 0 {
		t.Fatalf("fetch failed: %v", err)
	}
}
