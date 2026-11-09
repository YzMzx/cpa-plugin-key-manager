package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestRejectedRequestDoesNotWaitForAuditStorageOrCaptureItsBody(t *testing.T) {
	m := transactionManager(t)
	if _, err := m.UpsertKeyRuleFromJSON([]byte(`{"api_key":"admission-key","max_concurrency":1}`)); err != nil {
		t.Fatal(err)
	}
	makeRequest := func(id string) []byte {
		raw, _ := json.Marshal(pluginapi.RequestInterceptRequest{RequestID: id, SourceFormat: "openai", Model: "m", Headers: http.Header{"Authorization": {"Bearer admission-key"}}, Body: []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("PRIVATE-LARGE-PROMPT ", 16000) + `"}]}`)})
		return raw
	}
	if _, err := m.handleRequestInterceptBefore(makeRequest("allowed")); err != nil {
		t.Fatal(err)
	}
	connection, err := m.usageStore.DB().Conn().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			_ = connection.Close()
		}
	}()
	result := make(chan pluginapi.RequestInterceptResponse, 1)
	go func() {
		raw, err := m.handleRequestInterceptBefore(makeRequest("denied"))
		if err != nil {
			result <- pluginapi.RequestInterceptResponse{}
			return
		}
		var envelope struct {
			Result pluginapi.RequestInterceptResponse `json:"result"`
		}
		_ = json.Unmarshal(raw, &envelope)
		result <- envelope.Result
	}()
	select {
	case response := <-result:
		if !response.Terminate || response.StatusCode != 429 {
			t.Fatalf("not rejected: %+v", response)
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("429 response waited on audit SQL or full body processing")
	}
	_ = connection.Close()
	released = true
	for len(m.rejectedAuditSlots) > 0 {
		time.Sleep(time.Millisecond)
	}
	store, _ := m.auditSnapshot()
	records := auditRecords(t, m)
	for _, record := range records {
		if record.RequestID == auditCorrelationID("denied") {
			detail, e := store.Detail(context.Background(), record.ID)
			if e != nil {
				t.Fatal(e)
			}
			if detail.RequestBody != "" || detail.BodySHA256 != "" || detail.Outcome != "rejected" || detail.BodyState != "omitted_rejected" {
				t.Fatal("rejected body was processed or persisted")
			}
			return
		}
	}
	t.Fatal("rejected metadata missing after storage released")
}
