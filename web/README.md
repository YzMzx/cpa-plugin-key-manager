# Embedded UI runtime

The page remains one self-contained HTML document. Go embeds and concatenates the dependency-free runtime modules before the page script inside the existing application script block; no sibling asset URLs, npm packages, bundler or frontend server are required.

## Modules

- `client.js`: authenticated JSON client, 15-second full-request timeout, response validation, cancellation, unauthorized callback and optimistic revision header.
- `state.js`: latest-request ownership and per-overview key/model/credential indexes.
- `formatters.js`: configured IANA timezone formatting and local calendar boundaries, including DST days.
- `auth.js`: explicit same-origin parent authentication handshake.
- `events.js`: delegated events for generated data attributes; values are never interpreted as JavaScript.
- `dialogs.js`: native modal lifecycle, close/cancel cleanup, feature-detected backdrop dismissal and bounded CSS exit fallback without manual focus traps.
- `audit.js`: administrator-only request audit controller, metadata paging/filtering, explicit read-only body fetch and sensitive-state cleanup.
- `app.js`: page rendering and orchestration. Static HTML handlers remain supported. Editors retain independent baselines/revisions and async results are owned by the authenticated session and modal opening.

## Backend contract

GET overview provides the existing summary, keys, default_policy, usage, auth_files and available_models together with:

- `timezone`: IANA zone. All display/range/query boundaries derive from it. Asia/Shanghai is only a fallback for older/invalid configuration; ledger is initially fetched after overview resolves.
- Each rule may include authoritative `quota_used_usd` so renamed keys and late usage use the backend quota lineage; older backends fall back to the local accumulated cost minus reset baseline.
- `rules_revision`: current rule revision. Mutations send `X-Key-Guard-Revision` automatically when a snapshot is available. HTTP 409 asks the user to refresh, not silently overwrite.
- `host_sync: {pending: boolean, error?: string, error_code?: string}`: a committed rule change can have pending host synchronization. The UI displays this state and any response warning; it does not claim host synchronization succeeded.

Mutations may return the complete overview or `{ok:true, overview:...}`. Key CRUD never PUTs CPA's global key list. Refresh GETs overview and ledger only; host synchronization is owned by the backend. Requests do not automatically retry writes, because a timeout can have an unknown commit outcome.

## Credential binding picker

The picker offers only current usable credentials. Disabled, unavailable and unknown entries are hidden unless already selected. Missing existing references are retained as visibly unregistered/deleted restrictions, never fabricated as active. They can be unchecked, but batch select and synthetic events cannot add them. Saving an unrelated field preserves these restrictions; clearing the last selection does not silently switch to the unrestricted pool. New draft selections that become invalid before save are rejected with a message instead of being grandfathered as saved bindings. Partial credential refreshes surface a safe auth_files_error warning without replaying stale active entries. Native labelled checkboxes retain keyboard semantics. Name, ID and auth_index refer to the same row, and unchecking/batch clearing removes all matching aliases. Refresh updates an open key editor without discarding its draft.

## Parent authentication bridge

Embedded pages prefer the live same-origin CPA parent session over cached plugin credentials. Saved CPA storage supports `enc::v2::` (host-bound, independent of user agent), legacy `enc::v1::`, and existing plaintext formats; records for a different API origin or with `rememberPassword:false` are not reused. Malformed records do not prevent independent legacy aliases from being checked. Framework-private hooks and XHR interception are not used. The parent bridge uses this protocol:

1. Plugin posts to its exact origin: `{channel:"cpa-plugin-key-manager:auth:v1", type:"request", nonce}`.
2. Parent must verify the event origin and that event.source is the intended plugin iframe, and only reply while authenticated.
3. Parent responds to event.source with the same exact target origin: `{channel:"cpa-plugin-key-manager:auth:v1", type:"response", nonce, managementKey}`.
4. Plugin accepts only its actual parent, exact origin, exact channel/type and matching unpredictable nonce. Waiting is bounded to 450ms. Browser crypto.getRandomValues supplies the fallback nonce on HTTP contexts without randomUUID.

5. Parent announces `{channel:"cpa-plugin-key-manager:auth:v1",type:"ready"}` when its bridge is ready or the iframe loads. The child retries discovery only when locked. Parent sends the same channel with `type:"logout"` when the session changes, ends, or the resource is removed. Both notifications must come from the actual parent and exact origin. Bridge-derived credentials stay in memory and clear previous plugin session caches, so iframe removal cannot leave a reusable temporary host key in tab storage. Logout cancels discovery/API work and clears sensitive state; late responses cannot unlock the page. After a bridge has been detected, a timeout never falls back to stale saved credentials.

The matching parent implementation is in the CPA management frontend (`src/features/plugins/PluginResourcePage.tsx` and `pluginAuthBridge.ts`). Deploy its built single-file management page together with the rebuilt plugin to unlock non-persisted sessions automatically. The parent restricts sharing to this plugin's declared `/v0/resource/plugins/cpa-plugin-key-manager/ui` frame. This protocol intentionally requires same-origin hosting. The portable parent patch, pinned upstream revision and deployment steps are tracked in `integrations/README.md` and included in release archives.

Older CPA pages without the bridge can still reuse compatible saved credentials or the plugin tab session. Without those, manual Management Key input remains available, with a “重试后台登录” action for a delayed host connection. Backend validation still authorizes every request. There are no automatic retries after rejected credentials or replayed writes. Logout/401/403 closes modals, clears sensitive state and cancels outstanding operations.

## Tests

Run from repository root, without npm installation:

~~~text
node --test web/*.test.cjs
go test ./web
~~~

Node tests exercise pure helpers and the actual page functions in a minimal DOM/transport fixture: special characters, static handler availability, checkbox/drag/popover delegation, client errors/timeouts/revisions, late responses, auth cleanup, bridge validation/fallback, DST boundaries and local repaint behavior. This fixture is not a real browser rendering test. Go tests check single-document embedding and module order without opening a database.

Performance changes are structural (snapshot indexes, cached model grouping, account/key-only repaint, cached timezone formatters). They are not a measured production throughput claim; data-scale profiling should precede pagination/virtualization or backend query redesign.

## Native modal dialogs

The key and price editors and audit drawer use `showModal()`/`close()`, labelled headings and explicit autofocus controls. CSS `@starting-style`, `display`/`overlay` transitions and `transition-behavior: allow-discrete` animate entry/exit and backdrops; transforms only apply for no-preference motion, with a short fade for reduced motion. Modal validation errors render inside the active dialog because page-level toasts are behind the top layer.

Without native `closedby`, primary pointer down/up must both be outside the dialog bounds to dismiss; padding clicks and text-selection drags stay open. Exit support is checked with both `overlay` and an actual computed-display transition probe (CSS parsing alone can lie). Missing support keeps the dialog open with `data-closing` until all CSS animations settle, bounded to two seconds; reopening invalidates old close work. Close/cancel clears async price/audit ownership. Authentication loss and audit tab exit force immediate close and clear sensitive content, not an animated linger. Native focus containment and focus return are never recreated in JavaScript.

## Request audit contract

The administrator audit list uses only four visible filters: API Key (masked dropdown), key remark, model name and outcome. API Key selection sends only the backend-generated 64-hex fingerprint, never a plaintext key in the URL. Remarks and requested/served models use literal case-insensitive contains matching; outcome uses an exact match. Legacy request/trace/time query parameters remain backend-compatible but are not shown in the form.

- GET `/v0/management/key-guard/audit?limit=50&offset=0&key_fingerprint=&key_label=&model=&outcome=` returns `{items,total,limit,offset,status}`, without request bodies.
- GET `/audit/detail?id=<opaque-id>` returns `{record,status}` on an explicit click. A viewport-fixed responsive native `<dialog>` drawer opens immediately, tracks the selected row, supports previous/next on the same page and Esc/backdrop close. The browser owns focus containment/restoration and inert background behavior. CSS contains scroll chains on the modal and backdrop without changing root overflow; non-scrollable containment degrades progressively in older browsers. Provenance metadata is collapsed initially, so the body is near the top. Closing/tab-exit/lock aborts and clears the detail.
- GET `/audit/status` returns safe health/limits. GET `/audit/storage` calculates audit logical bytes, retained body bytes, active/expired counts and shared database/WAL file sizes. Physical bytes include other tables; cleanup does not guarantee an immediate smaller file or secure erasure.
- POST `/audit/cleanup/preview` accepts `{scope:"expired"|"before"|"all",before?:RFC3339}` and returns an identity-bound five-minute single-use token plus the snapshot count/bytes. Each oldest-first snapshot is limited to 1000 records and 32 MiB of payload/metadata work; `limited` and `remaining_records` explicitly describe rows outside this batch. The UI announces that only this batch will be deleted; further batches require a new preview and explicit confirmation, never automatic continuation. UI offers expired, 1/3/7 days ago, custom cutoff, all.
- POST `/audit/cleanup` requires `{token,confirm:true}`. The checkbox and explicit confirm are required; changing scope/date invalidates the local preview. Requests never automatically retry a write. Only snapshotted audit rows are deleted; newer rows, rules and usage remain untouched.

Dates use RFC3339 and display follows the configured timezone. The audit UI no longer collects, filters, displays or explains client/peer IP metadata. Legacy response IP fields and unknown-IP warnings are ignored rather than rendered. The requested long privacy banner is removed from the page; retention and administrator-access bounds still apply. New `stored_raw` bodies are plaintext, unredacted JSON request bytes up to 10 MiB. New captures use a two-space whitespace-only formatter before persistence; field order, duplicate keys, number lexemes, JSON escapes and plaintext values are not parsed into objects or changed. The saved hash matches the saved formatted representation. If indentation would exceed the retained-body budget, the backend keeps the complete original rather than dropping it. The detail view defaults to whitespace-only formatting for historical records too, with a “保存原文” toggle showing the exact saved string; this display never rewrites old rows or hashes. Rendering remains inert `textContent`, including credential/PII strings. A short detail hint identifies this sensitivity without reintroducing the removed long banner. `stored_raw` is shown only when `body_truncated` is false; there is no new raw partial mode. The former JSON element-count retention cap is removed. Legacy `stored_partial` records contain valid redacted JSON plus `[OMITTED:...]` placeholder strings for material that could not safely be retained; `body_truncated:true` on this explicit state means partial safe retention, not omission of the entire record. Other `omitted_*` and unknown states never expose any accidental body. Legacy `omitted_element_limit` records had no stored body and cannot be recovered; their explanation identifies the old-version behavior rather than a current limit. Detail shows retained UTF-8 byte size, complete/plaintext or legacy-partial status, and the retained-content SHA-256. The hash describes saved content, not necessarily redacted content and not tampe... (line truncated to 2000 chars)

List/status/storage/detail/preview/apply use independent request gates. Auth lock clears filters, pending confirmation and body, and cancels in-flight calls; late responses cannot repopulate them. Tests use fixture DOM/network, not a real browser renderer.

The audit table has eight columns after removal of the two network columns. The detail drawer, storage occupation calculation, scope preview and explicitly confirmed cleanup remain unchanged. All body rendering is inert `textContent`, including raw credentials, HTML-looking strings and legacy partial JSON containing placeholders. Legacy values over 256 Ki characters retain compact JSON presentation to avoid a second pretty-printed copy. Plaintext records can be toggled between formatted display and exact saved representation at every size. Formatting is a lexical whitespace transform, never JSON.parse/JSON.stringify over an object: duplicate names and arbitrary-precision numbers survive. Display expansion is capped; when excessive the complete saved text is shown without truncation. Lock/close clears the retained record reference and both display modes. No old element-count cap is reintroduced.

## Unified settings tab

The `tab-settings` page uses the administrator-only settings API. Hot settings are grouped into redacted-safe runtime configuration: audit collection/retention/record and byte limits, usage flush interval/ledger retention/timezone, and pricing URL/interval/timeout/include-usage/cache path. MiB inputs convert exactly to integer bytes; the audit total capacity maximum is 10240 MiB (10 GiB), while the default remains 64 MiB and each confirmed cleanup remains limited to 1000 records / 32 MiB. Invalid, non-finite or fractional integer values never reach a PUT. Price URL must be HTTP(S) without userinfo, query (including an empty trailing `?`) or fragment.

- GET `/v0/management/key-guard/settings` supplies `settings,rules_revision,limits,apply_status,bootstrap`. The editor renders only the current explicit runtime groups and startup fields, never arbitrary backend fields.
- PUT to that endpoint sends the complete hot `settings` object, matching `expected_revision` and explicit `X-Key-Guard-Revision`, plus `ack_prune`. Lower retention/count/total capacity or ledger retention requires a separate checkbox. Saved success is rebased only after backend confirmation; a post-save overview refresh failure is reported separately. `apply_status.ok:false` remains visible as saved but not fully applied.
- Bootstrap edits use a separate PUT `/settings/bootstrap` with `expected_file_revision,bootstrap,ack_restart,ack_storage_path_change`. Only `enabled,priority,usage_db_file` are accepted and sent as startup values. Current effective values and staged disk values are distinct. Database path is disabled if environment-locked. The form warns to back up and that host watching may apply changes early or invalidate the current page; a database path change needs restart and never migrates data automatically.

Drafts are independent from overview snapshots. Refresh and late GET responses cannot overwrite dirty edits; conflicts retain the draft and require reload/discard before retry. Tab exit cancels settings reads/writes while preserving the current ordinary draft. Authentication lock cancels work and clears every field, baseline and draft. Navigation cards open the existing key, default-policy and price editors rather than rebuilding those mechanisms. All content is text nodes and existing event bindings; the settings module is inlined before page startup in the same two-script standalone HTML.

Before audit persistence, root request message arrays (`messages`, `input`, `contents` or a root array) omit complete entries with role `system`, `developer` or `tool`. This does not edit the upstream request or recursively reinterpret business/tool output JSON. `stored_raw_system_filtered` and `stored_raw_system_media_filtered` are plaintext display states, with role/media filter labels and hashes over the retained formatted content. Historical rows are not rewritten by this change.

## Concise audit body status labels

The list and detail status use one saved label, `已保存 JSON 明文`, for accepted complete/plaintext, filtered and legacy saved states. Omitted codes group into no-body, limit, unsupported format, malformed format, disabled, busy and a generic not-saved label. Internal codes, retained bodies, hashes and collection/filter policies are unchanged. Size and legacy redacted/partial completeness stay in a separate detail information line. Unknown or contradictory truncated states never expose a body; changing wording must not relax the existing display whitelist. Closing/locking clears both status and extra information.

Default-policy edits use an independent dirty draft and the revision observed when it was loaded; overview refreshes or unrelated mutations do not overwrite it. Explicit discard reloads the latest values; conflicts keep the draft. Key and price modal openings likewise capture their baseline and revision together, and POST an explicit opening revision rather than a later global overview revision. Missing revisions require reopening after a fresh overview; writes never silently fall back to a newer revision.

Key/default-policy payloads merge editable controls onto the captured full baseline, preserving provider/attribute/strict binding restrictions and unshown fields such as default quota limits. Legacy credential aliases remain untouched until selection changes, then the explicitly edited selection replaces both alias fields. Wildcard/exclusion model rules (including `!*`) remain selected, visible and exported together; switching to unrestricted models or clearing specific credential restrictions requires confirmation. The credential checkbox only removes explicit credential identities, never other binding restrictions. Those currently uneditable restrictions are retained and announced in the badge.

Lock revokes a session epoch as well as request gates. Every mutation consumer rechecks the epoch after await, even when the underlying client Promise already settled; a new login cannot adopt an old reply. Modal close/reopen has separate ownership so old saves cannot close, annotate or restore controls on a new draft. Settings/audit mutation cleanup also respects request ownership. Lock clears baseline/selection/expanded/drag state, search fields, charts, tooltip, toast, price metadata and sensitive DOM, rather than merely hiding the workspace. An already submitted mutation may still commit server-side after cancellation; refresh to determine its outcome, never automatically retry it.

Key deletion sends `api_key` in the DELETE JSON body, never the URL. Locally denied requests can use `omitted_rejected`, displayed as `未保存（请求已拒绝）`. Processing work/time exhaustion uses `omitted_processing_limit`, displayed as `未保存（处理超限）` with an explicit whole-body omission explanation; concurrency saturation remains `omitted_busy`. Accidental bodies in omitted records remain hidden in both display modes.
