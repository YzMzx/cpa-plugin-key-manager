package audit

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/YzMzx/cpa-plugin-key-manager/internal/sqlitestore"
)

func TestAuditStorageIndexMigrationPreservesAndTracksBodies(t *testing.T) {
	db, _ := openAuditDB(t)
	// Simulate a v3 database containing pre-existing audit and unrelated data.
	for _, query := range []string{
		"DROP INDEX client_request_audit_storage_idx",
		"DELETE FROM schema_migrations WHERE version=4",
		"INSERT INTO rules_state(id,payload,updated_at) VALUES(1,'keep-rules','now')",
		"INSERT INTO key_usage(api_key,total_requests) VALUES('keep-key',9)",
	} {
		if _, err := db.Conn().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	s := NewStore(db, Config{Enabled: true})
	mustBegin(t, s, auditRecord("existing"))
	for i := 0; i < 2; i++ {
		if err := sqlitestore.Migrate(context.Background(), db.Conn()); err != nil {
			t.Fatal(err)
		}
	}
	var applied int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=4").Scan(&applied); err != nil || applied != 1 {
		t.Fatalf("migration count=%d err=%v", applied, err)
	}
	initial, err := s.Storage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(context.Background(), Completion{RequestID: "existing", ServedModel: "a-longer-served-model", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	completed, err := s.Storage(context.Background())
	if err != nil || completed.RequestBodyBytes != initial.RequestBodyBytes || completed.LogicalBytes == initial.LogicalBytes {
		t.Fatalf("completion left stale metadata: %+v %v", completed, err)
	}
	body := auditRecord("existing").RequestBody
	for _, next := range []string{body, `{"message":"你好 🌍"}`, ""} {
		if next != body {
			if _, err := db.Conn().Exec("UPDATE client_request_audit SET request_body=?,logical_bytes=?", next, len(next)+256); err != nil {
				t.Fatal(err)
			}
		}
		usage, err := s.Storage(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		plan, err := s.PreviewCleanup(context.Background(), "all", time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if usage.Records != 1 || usage.RequestBodyBytes != int64(len(next)) || plan.Records != 1 || plan.BodyBytes != usage.RequestBodyBytes || plan.LogicalBytes != usage.LogicalBytes {
			t.Fatalf("index not current: usage=%+v plan=%+v", usage, plan)
		}
		var retained string
		if err := db.Conn().QueryRow("SELECT request_body FROM client_request_audit").Scan(&retained); err != nil || retained != next {
			t.Fatal("migration changed retained body", err)
		}
	}
	if _, err := db.Conn().Exec("DELETE FROM client_request_audit"); err != nil {
		t.Fatal(err)
	}
	usage, err := s.Storage(context.Background())
	if err != nil || usage.Records != 0 || usage.ActiveRecords != 0 || usage.ExpiredRecords != 0 || usage.LogicalBytes != 0 || usage.RequestBodyBytes != 0 {
		t.Fatalf("wrong empty storage: %+v %v", usage, err)
	}
	var rules string
	if err := db.Conn().QueryRow("SELECT payload FROM rules_state WHERE id=1").Scan(&rules); err != nil || rules != "keep-rules" {
		t.Fatal("rules changed", err)
	}
	var requests int
	if err := db.Conn().QueryRow("SELECT total_requests FROM key_usage WHERE api_key='keep-key'").Scan(&requests); err != nil || requests != 9 {
		t.Fatal("usage changed", err)
	}
}

func TestAuditStorageQueriesNeverReadBodyPayloads(t *testing.T) {
	db, _ := openAuditDB(t)
	var tableRoot int
	if err := db.Conn().QueryRow("SELECT rootpage FROM sqlite_schema WHERE name='client_request_audit'").Scan(&tableRoot); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, query string
		args        []any
	}{
		{"storage", auditStorageQuery, []any{0, 0}},
		{"preview_all", auditCleanupPreviewQuery + "1=1 ORDER BY started_at,id LIMIT ?", []any{100001}},
		{"preview_before", auditCleanupPreviewQuery + "started_at<? ORDER BY started_at,id LIMIT ?", []any{1, 100001}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.Conn().Query("EXPLAIN "+tc.query, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			indexedColumns := 0
			tableCursors := make(map[int]bool)
			for rows.Next() {
				var addr, p1, p2, p3, p5 int
				var opcode string
				var p4, comment sql.NullString
				if err := rows.Scan(&addr, &opcode, &p1, &p2, &p3, &p4, &p5, &comment); err != nil {
					t.Fatal(err)
				}
				// DeferredSeek alone does not read the table. Identify actual table
				// cursors by root page rather than depending on planner cursor numbers.
				if opcode == "OpenRead" && p2 == tableRoot {
					tableCursors[p1] = true
				}
				if opcode == "Column" && tableCursors[p1] {
					t.Fatalf("reads audit table column %d instead of metadata index", p2)
				}
				if opcode == "Column" && !tableCursors[p1] {
					indexedColumns++
				}
				if opcode == "Function" && strings.HasPrefix(p4.String, "length(") {
					t.Fatal("recomputes body lengths")
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if indexedColumns == 0 {
				t.Fatal("did not read metadata index")
			}
		})
	}
}
