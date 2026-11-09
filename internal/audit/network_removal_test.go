package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func assertNoNetworkFields(t *testing.T, r Record) {
	t.Helper()
	if r.ClientIP != "" || r.PeerIP != "" || r.IPSource != "" || r.IPNote != "" {
		t.Fatalf("network information returned: %+v", r)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"client_ip", "peer_ip", "ip_source", "ip_note"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Fatalf("network field serialized: %s", raw)
		}
	}
}

func TestAuditDiscardsEveryLegacyNetworkInputAndNeverReturnsIt(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	rec := auditRecord("discard-network")
	rec.ClientIP = "invalid\x00"
	rec.PeerIP = strings.Repeat("private-peer", 1000)
	rec.IPSource = "host_resolved"
	rec.IPNote = "用户的连接说明"
	mustBegin(t, store, rec)
	metadata := oneRecord(t, store, rec.RequestID)
	assertNoNetworkFields(t, metadata)
	var client, peer, source, note string
	if err := db.Conn().QueryRow("SELECT client_ip,peer_ip,ip_source,ip_note FROM client_request_audit WHERE id=?", metadata.ID).Scan(&client, &peer, &source, &note); err != nil {
		t.Fatal(err)
	}
	if client != "" || peer != "" || source != "" || note != "" {
		t.Fatal("network input persisted")
	}
	// Even legacy values injected after migration must not be selected or returned.
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET client_ip='203.0.113.7',peer_ip='192.0.2.8',ip_source='legacy',ip_note='private' WHERE id=?", metadata.ID); err != nil {
		t.Fatal(err)
	}
	detail, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkFields(t, detail)
	metadata = oneRecord(t, store, rec.RequestID)
	assertNoNetworkFields(t, metadata)
	if _, err := store.List(context.Background(), Query{IP: "203.0.113.7"}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatal("deprecated IP query accepted")
	}

}

func TestAuditMigration3PurgesNetworkBytesAndPreservesHistory(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	rec := auditRecord("migration-network")
	rec.RequestBody = `{"messages":[{"content":"用户自己写的 IP 203.0.113.1"}]}`
	sum := sha256.Sum256([]byte(rec.RequestBody))
	rec.BodySHA256 = hex.EncodeToString(sum[:])
	mustBegin(t, store, rec)
	metadata := oneRecord(t, store, rec.RequestID)
	original, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes := logicalBytes(original)
	client, peer, source, note := "203.0.113.1", "2001:db8::1", "宿主来源", "含中文的连接备注"
	oldIPBytes := len(client) + len(peer) + len(source) + len(note)
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET client_ip=?,peer_ip=?,ip_source=?,ip_note=?,logical_bytes=? WHERE id=?", client, peer, source, note, originalBytes+int64(oldIPBytes), metadata.ID); err != nil {
		t.Fatal(err)
	}
	second := auditRecord("migration-no-negative")
	mustBegin(t, store, second)
	other := oneRecord(t, store, second.RequestID)
	if _, err := db.Conn().Exec("UPDATE client_request_audit SET client_ip='203.0.113.9',ip_note='字节',logical_bytes=1 WHERE id=?", other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("INSERT INTO rules_state(id,payload,updated_at) VALUES(1,'preserved-rules','now')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("INSERT INTO key_usage(api_key,total_requests,input_tokens,total_cost_nano_usd) VALUES('preserved-key',9,42,1234)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("DELETE FROM schema_migrations WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec("CREATE INDEX IF NOT EXISTS client_request_audit_ip_idx ON client_request_audit(client_ip,started_at)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := sqlitestore.Migrate(context.Background(), db.Conn()); err != nil {
			t.Fatal(err)
		}
	}
	var networkBytes, storedBytes int64
	if err := db.Conn().QueryRow("SELECT SUM(length(CAST(client_ip AS BLOB))+length(CAST(peer_ip AS BLOB))+length(CAST(ip_source AS BLOB))+length(CAST(ip_note AS BLOB))) FROM client_request_audit").Scan(&networkBytes); err != nil || networkBytes != 0 {
		t.Fatalf("historical network values remain: %d %v", networkBytes, err)
	}
	if err := db.Conn().QueryRow("SELECT logical_bytes FROM client_request_audit WHERE id=?", metadata.ID).Scan(&storedBytes); err != nil || storedBytes != originalBytes {
		t.Fatalf("incorrect UTF8 byte deduction: got %d want %d err %v", storedBytes, originalBytes, err)
	}
	if err := db.Conn().QueryRow("SELECT logical_bytes FROM client_request_audit WHERE id=?", other.ID).Scan(&storedBytes); err != nil || storedBytes != 0 {
		t.Fatal("logical byte count became negative")
	}
	got, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertNoNetworkFields(t, got)
	if got.RequestBody != original.RequestBody || got.BodySHA256 != original.BodySHA256 || got.RequestID != original.RequestID {
		t.Fatal("network purge changed request body/hash/history")
	}
	var payload string
	var requests, tokens, cost int64
	if err := db.Conn().QueryRow("SELECT payload FROM rules_state WHERE id=1").Scan(&payload); err != nil || payload != "preserved-rules" {
		t.Fatal("rules changed")
	}
	if err := db.Conn().QueryRow("SELECT total_requests,input_tokens,total_cost_nano_usd FROM key_usage WHERE api_key='preserved-key'").Scan(&requests, &tokens, &cost); err != nil || requests != 9 || tokens != 42 || cost != 1234 {
		t.Fatal("usage changed")
	}
	var count int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=3").Scan(&count); err != nil || count != 1 {
		t.Fatal("migration not idempotent")
	}
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='client_request_audit_ip_idx'").Scan(&count); err != nil || count != 0 {
		t.Fatal("network monitoring index retained")
	}
}

func TestAuditStoredPartialBodyPersistsWithHashAndNoListBody(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	rec := auditRecord("stored-partial")
	rec.BodyState = "stored_partial"
	rec.BodyTruncated = true
	rec.RequestBody = `{"messages":[{"content":"安全片段"}],"large_field":"[OMITTED:limit]"}`
	hash := sha256.Sum256([]byte(rec.RequestBody))
	rec.BodySHA256 = hex.EncodeToString(hash[:])
	mustBegin(t, store, rec)
	metadata := oneRecord(t, store, rec.RequestID)
	if metadata.RequestBody != "" || metadata.BodyState != "stored_partial" || !metadata.BodyTruncated {
		t.Fatal("partial list incorrect")
	}
	detail, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.RequestBody != rec.RequestBody || detail.BodySHA256 != rec.BodySHA256 || !detail.BodyTruncated {
		t.Fatal("safe partial JSON was discarded")
	}
	bad := rec
	bad.RequestID = "bad-partial"
	bad.BodySHA256 = strings.Repeat("0", 64)
	mustBegin(t, store, bad)
	badMeta := oneRecord(t, store, bad.RequestID)
	badDetail, err := store.Detail(context.Background(), badMeta.ID)
	if err != nil {
		t.Fatal(err)
	}
	if badDetail.RequestBody != "" || badDetail.BodySHA256 != "" {
		t.Fatal("bad partial hash persisted")
	}
}

func TestAuditPartialJSONArrayPersistsWithoutNetworkFields(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	rec := auditRecord("partial-array")
	rec.BodyState = "stored_partial"
	rec.BodyTruncated = true
	rec.RequestBody = `[{"content":"safe remainder"},"[OMITTED:limit]"]`
	sum := sha256.Sum256([]byte(rec.RequestBody))
	rec.BodySHA256 = hex.EncodeToString(sum[:])
	mustBegin(t, store, rec)
	metadata := oneRecord(t, store, rec.RequestID)
	detail, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.RequestBody != rec.RequestBody || detail.BodySHA256 != rec.BodySHA256 || !detail.BodyTruncated {
		t.Fatal("valid partial JSON array dropped")
	}
	assertNoNetworkFields(t, detail)
}

func TestAuditStoredRawPreservesExactJSONWithoutCollectingNetworkFields(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	rec := auditRecord("stored-raw")
	rec.BodyState = "stored_raw"
	rec.BodyTruncated = false
	rec.RequestBody = "{\n  \"messages\": [{\"role\": \"user\", \"content\": \"用户自行写入 secret-value 203.0.113.1\"}],\n  \"secret_key\": \"body-value-kept-exactly\"\n}  \n"
	sum := sha256.Sum256([]byte(rec.RequestBody))
	rec.BodySHA256 = hex.EncodeToString(sum[:])
	rec.ClientIP = "203.0.113.9"
	rec.PeerIP = "192.0.2.1"
	mustBegin(t, store, rec)
	metadata := oneRecord(t, store, rec.RequestID)
	if metadata.RequestBody != "" {
		t.Fatal("list exposed raw body")
	}
	detail, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.BodyState != "stored_raw" || detail.BodyTruncated || detail.RequestBody != rec.RequestBody || detail.BodySHA256 != rec.BodySHA256 {
		t.Fatalf("exact raw JSON was changed: %s", detail.RequestBody)
	}
	assertNoNetworkFields(t, detail)
}

func TestAuditStoredRawDoesNotApplySanitizerStructuralLimits(t *testing.T) {
	db, _ := openAuditDB(t)
	store := NewStore(db, Config{Enabled: true})
	rec := auditRecord("raw-structural")
	rec.BodyState = "stored_raw"
	rec.RequestBody = `{"messages":[{"role":"user","content":"` + strings.Repeat("plain value ", 1000) + `"}],"nested":` + strings.Repeat("[", 50) + `"original"` + strings.Repeat("]", 50) + `}`
	sum := sha256.Sum256([]byte(rec.RequestBody))
	rec.BodySHA256 = hex.EncodeToString(sum[:])
	mustBegin(t, store, rec)
	metadata := oneRecord(t, store, rec.RequestID)
	detail, err := store.Detail(context.Background(), metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.RequestBody != rec.RequestBody || detail.BodySHA256 != rec.BodySHA256 || detail.BodyTruncated {
		t.Fatal("raw JSON incorrectly subjected to sanitizer limits")
	}
}
