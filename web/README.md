# Embedded UI runtime

The page remains one self-contained HTML document. Go embeds and concatenates the dependency-free runtime modules before the page script inside the existing application script block; no sibling asset URLs, npm packages, bundler or frontend server are required.

## Modules

- `client.js`: authenticated JSON client, 15-second full-request timeout, response validation, cancellation, unauthorized callback and optimistic revision header.
- `state.js`: latest-request ownership and per-overview key/model/credential indexes.
- `formatters.js`: configured IANA timezone formatting and local calendar boundaries, including DST days.
- `auth.js`: explicit same-origin parent authentication handshake.
- `events.js`: delegated events for generated data attributes; values are never interpreted as JavaScript.
- `audit.js`: administrator-only request audit controller, metadata paging/filtering, explicit read-only body fetch and sensitive-state cleanup.
- `app.js`: page rendering and orchestration. Static HTML handlers remain supported. The default-policy draft behavior (review item 16) is intentionally unchanged.

## Backend contract

GET overview provides the existing summary, keys, default_policy, usage, auth_files and available_models together with:

- `timezone`: IANA zone. All display/range/query boundaries derive from it. Asia/Shanghai is only a fallback for older/invalid configuration; ledger is initially fetched after overview resolves.
- Each rule may include authoritative `quota_used_usd` so renamed keys and late usage use the backend quota lineage; older backends fall back to the local accumulated cost minus reset baseline.
- `rules_revision`: current rule revision. Mutations send `X-Key-Guard-Revision` automatically when a snapshot is available. HTTP 409 asks the user to refresh, not silently overwrite.
- `host_sync: {pending: boolean, error?: string, error_code?: string}`: a committed rule change can have pending host synchronization. The UI displays this state and any response warning; it does not claim host synchronization succeeded.

Mutations may return the complete overview or `{ok:true, overview:...}`. Key CRUD never PUTs CPA's global key list. Refresh GETs overview and ledger only; host synchronization is owned by the backend. Requests do not automatically retry writes, because a timeout can have an unknown commit outcome.

## Parent authentication bridge

Existing plugin session and same-origin saved CPA storage continue to unlock without another prompt. Framework-private hooks and XHR interception are not used. For non-persisted host sessions the parent can implement this explicit bridge:

1. Plugin posts to its exact origin: `{channel:"cpa-plugin-key-manager:auth:v1", type:"request", nonce}`.
2. Parent must verify the event origin and that event.source is the intended plugin iframe, and only reply while authenticated.
3. Parent responds to event.source with the same exact target origin: `{channel:"cpa-plugin-key-manager:auth:v1", type:"response", nonce, managementKey}`.
4. Plugin accepts only its actual parent, exact origin, exact channel/type and matching unpredictable nonce. Waiting is bounded to 450ms. Browser crypto.getRandomValues supplies the fallback nonce on HTTP contexts without randomUUID.

No parent-side bridge is added by this project. Without saved/shared state or an implemented bridge, manual Management Key input is the explicit safe fallback. Backend validation still authorizes the key. Logout/401/403 closes modals, clears sensitive state and cancels outstanding operations.

## Tests

Run from repository root, without npm installation:

~~~text
node --test web/runtime.test.cjs web/audit.test.cjs web/settings.test.cjs
go test ./web
~~~

Node tests exercise pure helpers and the actual page functions in a minimal DOM/transport fixture: special characters, static handler availability, checkbox/drag/popover delegation, client errors/timeouts/revisions, late responses, auth cleanup, bridge validation/fallback, DST boundaries and local repaint behavior. This fixture is not a real browser rendering test. Go tests check single-document embedding and module order without opening a database.

Performance changes are structural (snapshot indexes, cached model grouping, account/key-only repaint, cached timezone formatters). They are not a measured production throughput claim; data-scale profiling should precede pagination/virtualization or backend query redesign.

## Request audit contract

The administrator audit list uses only four visible filters: API Key (masked dropdown), key remark, model name and outcome. API Key selection sends only the backend-generated 64-hex fingerprint, never a plaintext key in the URL. Remarks and requested/served models use literal case-insensitive contains matching; outcome uses an exact match. Legacy request/trace/time query parameters remain backend-compatible but are not shown in the form.

- GET `/v0/management/key-guard/audit?limit=50&offset=0&key_fingerprint=&key_label=&model=&outcome=` returns `{items,total,limit,offset,status}`, without request bodies.
- GET `/audit/detail?id=<opaque-id>` returns `{record,status}` on an explicit click. A viewport-fixed responsive drawer opens immediately, tracks the selected row, supports previous/next on the same page, Esc/backdrop close, focus trapping and focus restoration without scrolling the list. Body scroll is locked while open. Provenance metadata is collapsed initially, so the body is near the top. Closing/tab-exit/lock aborts and clears the detail.
- GET `/audit/status` returns safe health/limits. GET `/audit/storage` calculates audit logical bytes, retained body bytes, active/expired counts and shared database/WAL file sizes. Physical bytes include other tables; cleanup does not guarantee an immediate smaller file or secure erasure.
- POST `/audit/cleanup/preview` accepts `{scope:"expired"|"before"|"all",before?:RFC3339}` and returns an identity-bound five-minute single-use token plus the snapshot count/bytes. UI offers expired, 1/3/7 days ago, custom cutoff, all.
- POST `/audit/cleanup` requires `{token,confirm:true}`. The checkbox and explicit confirm are required; changing scope/date invalidates the local preview. Requests never automatically retry a write. Only snapshotted audit rows are deleted; newer rows, rules and usage remain untouched.

Dates use RFC3339 and display follows the configured timezone. The audit UI no longer collects, filters, displays or explains client/peer IP metadata. Legacy response IP fields and unknown-IP warnings are ignored rather than rendered. The requested long privacy banner is removed from the page; retention and administrator-access bounds still apply. New `stored_raw` bodies are plaintext, unredacted JSON request bytes up to 10 MiB. New captures use a two-space whitespace-only formatter before persistence; field order, duplicate keys, number lexemes, JSON escapes and plaintext values are not parsed into objects or changed. The saved hash matches the saved formatted representation. If indentation would exceed the retained-body budget, the backend keeps the complete original rather than dropping it. The detail view defaults to whitespace-only formatting for historical records too, with a “保存原文” toggle showing the exact saved string; this display never rewrites old rows or hashes. Rendering remains inert `textContent`, including credential/PII strings. A short detail hint identifies this sensitivity without reintroducing the removed long banner. `stored_raw` is shown only when `body_truncated` is false; there is no new raw partial mode. The former JSON element-count retention cap is removed. Legacy `stored_partial` records contain valid redacted JSON plus `[OMITTED:...]` placeholder strings for material that could not safely be retained; `body_truncated:true` on this explicit state means partial safe retention, not omission of the entire record. Other `omitted_*` and unknown states never expose any accidental body. Legacy `omitted_element_limit` records had no stored body and cannot be recovered; their explanation identifies the old-version behavior rather than a current limit. Detail shows retained UTF-8 byte size, complete/plaintext or legacy-partial status, and the retained-content SHA-256. The hash describes saved content, not necessarily redacted content and not tampe... (line truncated to 2000 chars)

List/status/storage/detail/preview/apply use independent request gates. Auth lock clears filters, pending confirmation and body, and cancels in-flight calls; late responses cannot repopulate them. Tests use fixture DOM/network, not a real browser renderer.

The audit table has eight columns after removal of the two network columns. The detail drawer, storage occupation calculation, scope preview and explicitly confirmed cleanup remain unchanged. All body rendering is inert `textContent`, including raw credentials, HTML-looking strings and legacy partial JSON containing placeholders. Legacy values over 256 Ki characters retain compact JSON presentation to avoid a second pretty-printed copy. Plaintext records can be toggled between formatted display and exact saved representation at every size. Formatting is a lexical whitespace transform, never JSON.parse/JSON.stringify over an object: duplicate names and arbitrary-precision numbers survive. Display expansion is capped; when excessive the complete saved text is shown without truncation. Lock/close clears the retained record reference and both display modes. No old element-count cap is reintroduced.

## Unified settings tab

The `tab-settings` page uses the administrator-only settings API. Hot settings are grouped into redacted-safe runtime configuration: audit collection/retention/record and byte limits, usage flush interval/ledger retention/timezone, and pricing URL/interval/timeout/include-usage/cache path. MiB inputs convert exactly to integer bytes; 1024 MiB is 1 GiB. Invalid, non-finite or fractional integer values never reach a PUT. Price URL must be HTTP(S) without userinfo, query (including an empty trailing `?`) or fragment.

- GET `/v0/management/key-guard/settings` supplies `settings,rules_revision,limits,apply_status,bootstrap`. The editor renders only the current explicit runtime groups and startup fields, never arbitrary backend fields.
- PUT to that endpoint sends the complete hot `settings` object, matching `expected_revision` and explicit `X-Key-Guard-Revision`, plus `ack_prune`. Lower retention/count/total capacity or ledger retention requires a separate checkbox. Saved success is rebased only after backend confirmation; a post-save overview refresh failure is reported separately. `apply_status.ok:false` remains visible as saved but not fully applied.
- Bootstrap edits use a separate PUT `/settings/bootstrap` with `expected_file_revision,bootstrap,ack_restart,ack_storage_path_change`. Only `enabled,priority,usage_db_file` are accepted and sent as startup values. Current effective values and staged disk values are distinct. Database path is disabled if environment-locked. The form warns to back up and that host watching may apply changes early or invalidate the current page; a database path change needs restart and never migrates data automatically.

Drafts are independent from overview snapshots. Refresh and late GET responses cannot overwrite dirty edits; conflicts retain the draft and require reload/discard before retry. Tab exit cancels settings reads/writes while preserving the current ordinary draft. Authentication lock cancels work and clears every field, baseline and draft. Navigation cards open the existing key, default-policy and price editors rather than rebuilding those mechanisms. All content is text nodes and existing event bindings; the settings module is inlined before page startup in the same two-script standalone HTML.

Before audit persistence, root request message arrays (`messages`, `input`, `contents` or a root array) omit complete entries with role `system` or `developer`. This does not edit the upstream request or recursively reinterpret business/tool output JSON. `stored_raw_system_filtered` and `stored_raw_system_media_filtered` are plaintext display states, with role/media filter labels and hashes over the retained formatted content. Historical rows are not rewritten by this change.
