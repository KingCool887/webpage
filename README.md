## Debugging

### Server logs
Every proxied request (`/p/...`) and every WebSocket upgrade is appended to a
ring buffer (2000 entries) with:

- method, **decoded target URL**, response status, elapsed ms, content-type
- upstream fetch failures logged with the error message

Also echoed to stdout, so they appear in Render's dashboard log viewer.

Endpoints (both require the auth cookie):

- `GET /__logs` — JSON array of entries with a monotonic `id`
- `GET /__logs?after=<id>` — only entries newer than `id`
- `GET /__logs?format=txt` — plaintext, one JSON object per line

### Client logs
The runtime shim injected into every proxied page patches:

- `fetch`, `XMLHttpRequest`, `WebSocket`, `navigator.sendBeacon`
- `document.createElement` for `script` / `link` / `img`
- `Worker` (logged, not rewritten), `navigator.serviceWorker.register`
- `window.onerror` (both script and resource errors) and `unhandledrejection`

Each network call is logged with `method URL -> status (ms)` — including the
original URL and the proxified URL for WebSockets. Entries are batched (25 at a
time, or every 3s, or on `pagehide`) and POSTed to `/__log`, and mirrored to
the browser console as `[proxy-log] ...`.

### The Logs panel
The launcher toolbar has a **Logs** button. Clicking it opens a panel at the
bottom that polls `/__logs?after=<id>` every 1.5s and shows a merged stream of
server and client entries. Leave it open while loading Deadshot and it will
show exactly which request, WebSocket, or resource failed.

For a raw text log: `GET /__logs?format=txt` in a new tab.