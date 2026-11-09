# Embedded UI runtime

The page remains one self-contained HTML document. Go embeds and concatenates the dependency-free runtime modules before the page script inside the existing application script block; no sibling asset URLs, npm packages, bundler or frontend server are required.

## Modules

- `client.js`: authenticated JSON client, 15-second full-request timeout, response validation, cancellation, unauthorized callback and optimistic revision header.
- `state.js`: latest-request ownership and per-overview key/model/credential indexes.
- `formatters.js`: configured IANA timezone formatting and local calendar boundaries, including DST days.
- `auth.js`: explicit same-origin parent authentication handshake.
- `events.js`: delegated events for generated data attributes; values are never interpreted as JavaScript.
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
node --test web/runtime.test.cjs
go test ./web
~~~

Node tests exercise pure helpers and the actual page functions in a minimal DOM/transport fixture: special characters, static handler availability, checkbox/drag/popover delegation, client errors/timeouts/revisions, late responses, auth cleanup, bridge validation/fallback, DST boundaries and local repaint behavior. This fixture is not a real browser rendering test. Go tests check single-document embedding and module order without opening a database.

Performance changes are structural (snapshot indexes, cached model grouping, account/key-only repaint, cached timezone formatters). They are not a measured production throughput claim; data-scale profiling should precede pagination/virtualization or backend query redesign.
