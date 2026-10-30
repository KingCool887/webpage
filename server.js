const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { lookup } = require('node:dns/promises');
const { Readable } = require('node:stream');

const HOST = '127.0.0.1';
const BIND_ADDRESS = process.env.BIND_ADDRESS || '0.0.0.0';
const PORT = Number(process.env.PORT || 8787);
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
const PAGE_PATH = path.join(__dirname, 'index.html');
const USERS_PATH = path.join(__dirname, 'users.json');
const COOKIE_NAME = '__proxy_access';

// ---------- Users / auth ----------

let VALID_KEYS = new Set();
try {
  const raw = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
  const list = Array.isArray(raw.keys) ? raw.keys : [];
  VALID_KEYS = new Set(list.filter(u => u && u.active !== false).map(u => u.key));
  console.log(`Loaded ${VALID_KEYS.size} active key(s) from users.json`);
} catch (e) {
  console.error('Failed to load users.json:', e.message);
  console.error('Server will start, but every request will be rejected until users.json is fixed.');
}

function keyFromCookie(header) {
  const m = (header || '').match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}

function isAuthed(req) {
  const key = keyFromCookie(req.headers.cookie);
  return !!(key && VALID_KEYS.has(key));
}

// Returns true if the request may proceed. Handles the ?key= → cookie redirect.
function checkAuth(req, res) {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const queryKey = url.searchParams.get('key');

  if (queryKey) {
    if (!VALID_KEYS.has(queryKey)) {
      res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Access denied: unknown key.');
      return false;
    }
    url.searchParams.delete('key');
    const cleanPath = url.pathname + (url.search || '');
    const secure = (req.headers['x-forwarded-proto'] === 'https') ||
                   (req.socket && req.socket.encrypted) ? '; Secure' : '';
    res.writeHead(302, {
      'Location': cleanPath,
      'Set-Cookie': `${COOKIE_NAME}=${encodeURIComponent(queryKey)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`,
      'Cache-Control': 'no-store',
    });
    res.end();
    return false;
  }

  if (!isAuthed(req)) {
    res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Access denied. Open this URL with ?key=<your-key> once to get a session cookie.');
    return false;
  }
  return true;
}

// ---------- Target encoding ----------

function encodeTarget(value) {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function decodeTarget(value) {
  if (!/^[A-Za-z0-9_-]{1,12000}$/.test(value)) throw new Error('Invalid proxy address.');
  const target = new URL(Buffer.from(value, 'base64url').toString('utf8'));
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS are supported.');
  return target;
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
           (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  if (family === 6) return address === '::' || address === '::1' || address.startsWith('fc') ||
                         address.startsWith('fd') || address.startsWith('fe8');
  return true;
}

async function validatePublicTarget(target) {
  const hostname = target.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    throw new Error('Local addresses not supported.');
  }
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new Error('Private addresses not supported.');
    return;
  }
  const answers = await lookup(hostname, { all: true, verbatim: true });
  if (!answers.length || answers.some(a => isPrivateAddress(a.address))) {
    throw new Error('Did not resolve to public.');
  }
}

// ---------- URL rewriting ----------

function proxyPath(target) {
  return `/p/${encodeTarget(target.origin)}${target.pathname}${target.search}`;
}

function resolveLink(value, base) {
  const raw = value.trim();
  if (!raw || raw.startsWith('#') || /^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(raw)) return value;
  try {
    const resolved = new URL(raw, base);
    if (!['http:', 'https:'].includes(resolved.protocol)) return value;
    return proxyPath(resolved);
  } catch { return value; }
}

function rewriteCss(css, base) {
  return css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, v) => `url("${resolveLink(v, base)}")`);
}

function rewriteHtml(html, target) {
  const attrNames = ['href', 'src', 'action', 'formaction', 'poster', 'data', 'xlink:href'];
  const attrPattern = new RegExp(`(\\b(?:${attrNames.join('|')})\\s*=\\s*)(["'])(.*?)\\2`, 'gis');
  let rewritten = html.replace(attrPattern, (m, p, q, v) => `${p}${q}${resolveLink(v, target)}${q}`);
  rewritten = rewritten.replace(/<meta\b[^>]*http-equiv\s*=\s*(["'])?content-security-policy\1?[^>]*>/gi, '');

  const runtime = `<script>(function(){
    const TARGET_BASE = ${JSON.stringify(target.origin)};
    const TARGET_HOSTNAME = new URL(TARGET_BASE).hostname;
    const encode = value => btoa(unescape(encodeURIComponent(value))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');

    const proxify = value => {
      if (typeof value !== 'string') value = String(value);
      if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(value)) return value;
      try {
        const current = new URL(value, TARGET_BASE);
        if (!['http:','https:'].includes(current.protocol)) return value;
        if (!current.hostname.includes('.')) return value;
        // Already a proxy path — pass through
        if (current.pathname.startsWith('/p/')) return current.pathname + current.search;
        if (current.pathname.startsWith('/_ws/')) return current.pathname + current.search;
        // Resolved to proxy hostname? This is a relative URL the page wrote
        // against document base — rewrite to the target origin.
        if (current.hostname === window.location.hostname) {
          return '/p/' + encode(TARGET_BASE) + current.pathname + current.search;
        }
        // Different host — proxify to that host's origin.
        return '/p/' + encode(current.origin) + current.pathname + current.search;
      } catch { return value; }
    };

    // --- fetch / XHR ---
    const originalFetch = window.fetch.bind(window);
    window.fetch = async function(input, init){
      const request = input instanceof Request ? input : new Request(input, init);
      const proxified = proxify(request.url);
      const options = {
        method: request.method, headers: request.headers,
        mode: request.mode === 'navigate' ? 'cors' : request.mode,
        credentials: 'include',
        cache: request.cache, redirect: request.redirect, integrity: request.integrity, signal: request.signal,
      };
      if (request.body && !['GET', 'HEAD'].includes(request.method)) {
        options.body = await request.clone().arrayBuffer();
      }
      return originalFetch(proxified, options);
    };
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest){
      return originalOpen.call(this, method, proxify(String(url)), ...rest);
    };

    // --- WebSockets ---
    const NativeWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols){
      let newUrl = String(url);
      try {
        if (newUrl.startsWith('/_ws/')) return new NativeWebSocket(newUrl, protocols);

        const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const proxyHost = window.location.host;

        let resolved;
        if (newUrl.startsWith('ws://') || newUrl.startsWith('wss://')) {
          resolved = new URL(newUrl);
        } else if (newUrl.startsWith('//')) {
          resolved = new URL(wsProto + newUrl);
        } else if (newUrl.startsWith('/')) {
          // Relative path — treat as party server per design.
          resolved = new URL(wsProto + '//party.' + TARGET_HOSTNAME + newUrl);
        } else {
          return new NativeWebSocket(newUrl, protocols);
        }

        // Any WS that lands on the proxy hostname is redirected to party.<target>.
        let finalUrl;
        if (resolved.hostname === window.location.hostname) {
          finalUrl = wsProto + '//party.' + TARGET_HOSTNAME + resolved.pathname + resolved.search;
        } else {
          finalUrl = resolved.origin + resolved.pathname + resolved.search;
        }
        newUrl = wsProto + '//' + proxyHost + '/_ws/' + encode(finalUrl);
      } catch (e) {}
      return new NativeWebSocket(newUrl, protocols);
    };
    window.WebSocket.prototype = NativeWebSocket.prototype;
    window.WebSocket.CONNECTING = NativeWebSocket.CONNECTING;
    window.WebSocket.OPEN = NativeWebSocket.OPEN;
    window.WebSocket.CLOSING = NativeWebSocket.CLOSING;
    window.WebSocket.CLOSED = NativeWebSocket.CLOSED;

    // --- Service Worker registration ---
    if (navigator.serviceWorker) {
      const originalRegister = navigator.serviceWorker.register;
      navigator.serviceWorker.register = function(scriptURL, options){
        return originalRegister.call(this, proxify(scriptURL), options);
      };
    }

    // --- Dynamically created scripts/links ---
    const originalCreateElement = document.createElement.bind(document);
    document.createElement = function(tagName){
      const el = originalCreateElement(tagName);
      if (tagName.toLowerCase() === 'script' || tagName.toLowerCase() === 'link') {
        const originalSetAttribute = el.setAttribute;
        el.setAttribute = function(name, value){
          if (name.toLowerCase() === 'src' || name.toLowerCase() === 'href') value = proxify(value);
          return originalSetAttribute.call(el, name, value);
        };
      }
      return el;
    };

    // --- DOM URL property patching ---
    const patchUrlProperty = (prototype, property) => {
      const d = Object.getOwnPropertyDescriptor(prototype, property);
      if (!d || !d.get || !d.set || !d.configurable) return;
      Object.defineProperty(prototype, property, {
        configurable: d.configurable, enumerable: d.enumerable,
        get(){ return d.get.call(this); },
        set(value){ d.set.call(this, typeof value === 'string' ? proxify(value) : value); }
      });
    };
    patchUrlProperty(HTMLIFrameElement.prototype, 'src');
    patchUrlProperty(HTMLScriptElement.prototype, 'src');
    patchUrlProperty(HTMLImageElement.prototype, 'src');
    patchUrlProperty(HTMLLinkElement.prototype, 'href');
    patchUrlProperty(HTMLMediaElement.prototype, 'src');
  })();</script>`;

  if (/<head\b[^>]*>/i.test(rewritten)) rewritten = rewritten.replace(/<head\b[^>]*>/i, h => `${h}${runtime}`);
  else rewritten = runtime + rewritten;
  return rewritten;
}

// ---------- Proxying ----------

async function readRequestBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) throw new Error('Too large');
    chunks.push(chunk);
  }
  return size ? Buffer.concat(chunks) : undefined;
}

function rewriteSetCookie(header) {
  // Strip Domain so the cookie binds to the proxy host, keep Path/Secure/SameSite.
  return header.replace(/;\s*domain=[^;]*/gi, '');
}

async function proxyRequest(req, res, target) {
  try {
    await validatePublicTarget(target);
  } catch (e) {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Upstream blocked: ' + e.message);
  }

  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (['host', 'connection', 'content-length', 'origin', 'referer', 'cookie'].includes(lower)) continue;
    if (Array.isArray(value)) headers.set(name, value.join(', '));
    else headers.set(name, value);
  }
  const cookie = req.headers.cookie || '';
  const cleanCookie = cookie.split(';').map(c => c.trim())
    .filter(c => c && !c.startsWith(COOKIE_NAME + '=')).join('; ');
  if (cleanCookie) headers.set('cookie', cleanCookie);
  if (req.headers.origin) headers.set('origin', target.origin);

  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRequestBody(req);

  let upstream;
  try {
    upstream = await fetch(target, { method: req.method, headers, body, redirect: 'manual' });
  } catch (e) {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Upstream fetch failed: ' + e.message);
  }

  const outHeaders = new Headers(upstream.headers);
  for (const name of ['content-security-policy', 'x-frame-options', 'content-encoding',
                      'content-length', 'transfer-encoding', 'connection', 'set-cookie']) {
    outHeaders.delete(name);
  }

  // Preserve all upstream Set-Cookie values (Node fetch exposes them via getSetCookie).
  if (typeof upstream.headers.getSetCookie === 'function') {
    for (const c of upstream.headers.getSetCookie()) {
      outHeaders.append('set-cookie', rewriteSetCookie(c));
    }
  } else {
    const single = upstream.headers.get('set-cookie');
    if (single) outHeaders.set('set-cookie', rewriteSetCookie(single));
  }

  outHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
  outHeaders.set('Cross-Origin-Embedder-Policy', 'credentialless');
  outHeaders.set('referrer-policy', 'same-origin');
  outHeaders.set('access-control-allow-origin', '*');
  outHeaders.set('access-control-allow-credentials', 'true');

  const location = upstream.headers.get('location');
  if (location) {
    try { outHeaders.set('location', proxyPath(new URL(location, target))); } catch {}
  }

  const contentType = upstream.headers.get('content-type') || '';

  // Convert Headers to a plain object preserving repeated set-cookie.
  const headerObj = {};
  for (const [k, v] of outHeaders.entries()) {
    if (k.toLowerCase() === 'set-cookie') {
      (headerObj['set-cookie'] ||= []).push(v);
    } else {
      headerObj[k] = v;
    }
  }

  if (/text\/html/i.test(contentType)) {
    const html = rewriteHtml(await upstream.text(), target);
    headerObj['content-type'] = 'text/html; charset=utf-8';
    res.writeHead(upstream.status, headerObj);
    return res.end(html);
  }
  if (/text\/css/i.test(contentType)) {
    const css = rewriteCss(await upstream.text(), target);
    headerObj['content-type'] = 'text/css; charset=utf-8';
    res.writeHead(upstream.status, headerObj);
    return res.end(css);
  }

  res.writeHead(upstream.status, headerObj);
  if (!upstream.body || req.method === 'HEAD') return res.end();
  Readable.fromWeb(upstream.body).pipe(res);
}

// ---------- WS relay ----------

async function relayUpgrade(req, client, head, target) {
  const secure = target.protocol === 'wss:';
  const port = Number(target.port) || (secure ? 443 : 80);
  const upstream = secure
    ? tls.connect({ host: target.hostname, port, servername: target.hostname })
    : net.connect({ host: target.hostname, port });

  upstream.once(secure ? 'secureConnect' : 'connect', () => {
    const lines = [`${req.method} ${target.pathname}${target.search} HTTP/${req.httpVersion}`];
    for (const [name, value] of Object.entries(req.headers)) {
      const lower = name.toLowerCase();
      if (lower === 'host') lines.push(`Host: ${target.host}`);
      else if (lower !== 'cookie' && value) lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
    }
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head && head.length) upstream.write(head);
    client.pipe(upstream);
  });

  let responseBuffer = Buffer.alloc(0);
  const onUpstreamData = (chunk) => {
    responseBuffer = Buffer.concat([responseBuffer, chunk]);
    const end = responseBuffer.indexOf('\r\n\r\n');
    if (end < 0) return;
    client.write(responseBuffer);
    upstream.removeListener('data', onUpstreamData);
    upstream.pipe(client);
  };
  upstream.on('data', onUpstreamData);
  upstream.on('error', () => client.destroy());
  client.on('error', () => upstream.destroy());
}

// ---------- HTTP server ----------

const server = http.createServer({ timeout: 0 }, async (req, res) => {
  // CORS preflight — no auth, no body.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': '*',
    });
    return res.end();
  }

  if (!checkAuth(req, res)) return;

  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); }
  catch { return res.writeHead(400).end(); }

  if (local.pathname.startsWith('/p/')) {
    let target;
    try {
      const match = local.pathname.match(/^\/p\/([A-Za-z0-9_-]+)(\/.*)?$/);
      if (!match) throw new Error('Invalid path');
      target = decodeTarget(match[1]);
      if (match[2] && match[2] !== '/') { target.pathname = match[2]; target.search = local.search; }
      else if (local.search) target.search = local.search;
      else if (match[2] === '/') target.pathname = '/';
    } catch (e) {
      return res.writeHead(400).end(e.message);
    }
    return proxyRequest(req, res, target);
  }

  if (req.method === 'GET' && local.pathname === '/') {
    let page;
    try { page = fs.readFileSync(PAGE_PATH, 'utf8'); }
    catch { return res.writeHead(500).end('index.html missing'); }
    page = page.replaceAll('__PROXY_PORT__', String(PORT));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(page);
  }

  return res.writeHead(404).end('Not found');
});

server.on('upgrade', async (req, client, head) => {
  if (!isAuthed(req)) {
    client.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return client.destroy();
  }
  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); }
  catch { return client.destroy(); }

  let target;
  try {
    const match = local.pathname.match(/^\/_ws\/([A-Za-z0-9_-]+)(\/.*)?$/);
    if (!match) throw new Error('Invalid WS path');
    target = decodeTarget(match[1]);
    target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
    if (match[2]) target.pathname = match[2];
    if (local.search) target.search = local.search;
    await validatePublicTarget(target);
  } catch (e) {
    client.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    return client.destroy();
  }
  await relayUpgrade(req, client, head, target);
});

server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Proxy listening on ${BIND_ADDRESS}:${PORT}`);
  if (!VALID_KEYS.size) {
    console.warn('⚠️  No valid keys — every request will be rejected. Fix users.json.');
  }
});