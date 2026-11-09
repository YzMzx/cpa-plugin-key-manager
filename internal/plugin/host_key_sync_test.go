package plugin

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestHostDeltaPreservesConcurrentNativeKeysAndValidatesTLS(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			var mu sync.Mutex
			keys := []string{"native-kept", "removed"}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-secret" {
					w.WriteHeader(401)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					_ = json.NewEncoder(w).Encode(map[string]any{"api-keys": append([]string(nil), keys...)})
					// A native-admin writer acts after GET. Delta updates must not lose this key.
					keys = append(keys, "concurrent-native")
				case http.MethodPatch:
					var body struct{ Old, New string }
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					found := false
					for _, key := range keys {
						if key == body.New {
							found = true
						}
					}
					if !found {
						keys = append(keys, body.New)
					}
					_, _ = w.Write([]byte("{}"))
				case http.MethodDelete:
					target := r.URL.Query().Get("value")
					out := keys[:0]
					for _, key := range keys {
						if key != target {
							out = append(out, key)
						}
					}
					keys = out
					_, _ = w.Write([]byte("{}"))
				default:
					t.Errorf("unexpected whole-list operation %s", r.Method)
					w.WriteHeader(405)
				}
			}))
			if secure {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			parsed, _ := url.Parse(server.URL)
			port := parsed.Port()
			dir := t.TempDir()
			cfg := fmt.Sprintf("host: %s\nport: %s\n", parsed.Hostname(), port)
			if secure {
				cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
				if err := os.WriteFile(filepath.Join(dir, "server.pem"), cert, 0600); err != nil {
					t.Fatal(err)
				}
				cfg += "tls:\n  enable: true\n  cert: server.pem\n"
			}
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CPA_CONFIG_FILE", path)
			if err := syncHostRuntimeDelta(context.Background(), "test-secret", []string{"added"}, []string{"removed"}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			seen := map[string]bool{}
			for _, key := range keys {
				seen[key] = true
			}
			if !seen["native-kept"] || !seen["concurrent-native"] || !seen["added"] || seen["removed"] {
				t.Fatalf("wrong native keys %v", keys)
			}
		})
	}
}
