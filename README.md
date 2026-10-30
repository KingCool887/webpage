# Shared website proxy

A single-process HTTP + WebSocket reverse proxy with a small launcher page in
front of it. You run one Node process, open the launcher, type a site (default
`deadshot.io`), and the site loads inside an iframe with its URLs rewritten so
that every asset, fetch, XHR, and WebSocket request flows through the proxy.

It is intended for a small group of friends sharing a single deployment on
Render's free tier. Access is gated by per-person keys in `users.json`.

## How it works

- **Launcher page (`/`)** — a plain HTML page with an address bar and an iframe.
  Once authenticated, it auto-launches the default site so returning users land
  straight in the game.
- **Proxy (`/p/<base64-target>/...`)** — fetches the target, rewrites HTML/CSS
  URLs, strips frame-blocking headers, forwards cookies, and streams the body
  back. Non-HTML responses pass through unchanged.
- **WebSocket relay (`/_ws/<base64-target>/...`)** — tunnels WebSocket upgrades
  to the target. The in-page runtime rewrites `new WebSocket(...)` calls so the
  game's party server (e.g. `party.deadshot.io`) is reachable through the proxy.
  Any WS URL that resolves to the proxy hostname — including relative `/ws`
  paths — is redirected to `party.<target host>` per design.
- **Runtime shim** — injected into every proxied HTML page. It patches `fetch`,
  `XMLHttpRequest`, `WebSocket`, `document.createElement`, and URL properties
  on `HTMLIFrameElement` / `HTMLScriptElement` / `HTMLImageElement` /
  `HTMLLinkElement` / `HTMLMediaElement` so dynamically constructed URLs also go
  through the proxy.
- **Auth** — the launcher and every proxied request require an `access` cookie.
  You get it by visiting the launcher once with `?key=<one-of-your-users>`.

## Auth

`users.json` is the source of truth. Format:

```json
{ "keys": [ { "key": "Colin_4587", "name": "Colin", "active": true } ] }