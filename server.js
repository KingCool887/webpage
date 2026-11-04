const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { lookup } = require('node:dns/promises');
const { Readable } = require('node:stream');

const HOST = '127.0.0.1';
const BIND_ADDRESS = process.env.BIND_ADDRESS || '0.0.0.0';
const PORT = Number(process.env.PORT || 8787);
const PAGE_PATH = path.join(__dirname, 'index.html');
const USERS_PATH = path.join(__dirname, 'users.json');
const COOKIE_NAME = '__proxy_access';
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
const MAX_WS_PER_SESSION = 20;

const lastMatchIpByTarget = new Map();   // `${sessionId}:${targetOrigin}` -> 32-hex
const proxyHostTargets = new Map();       // sanitized req.host -> target origin (for legacy /ws)
const wsCountByKey = new Map();

// ---------- users ----------
let VALID_KEYS = new Set();
try {
  const raw = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
  const list = Array.isArray(raw.keys) ? raw.keys : [];
  VALID_KEYS = new Set(list.filter(u => u && u.active !== false).map(u => u.key));
  console.log(`Loaded ${VALID_KEYS.size} active key(s)`);
} catch (e) {
  console.error('users.json failed:', e.message);
}

function keyFromCookie(header) {
  const m = (header || '').match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}
function isAuthed(req) {
  const k = keyFromCookie(req.headers.cookie);
  return !!(k && VALID_KEYS.has(k));
}
function sessionId(req) {
  return keyFromCookie(req.headers.cookie) || 'anon';
}

function checkAuth(req, res) {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const q = url.searchParams.get('key');
  if (q) {
    if (!VALID_KEYS.has(q)) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      return res.end('Unknown key.'), false;
    }
    url.searchParams.delete('key');
    const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    res.writeHead(302, {
      Location: url.pathname + (url.search || ''),
      'Set-Cookie': `${COOKIE_NAME}=${encodeURIComponent(q)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`,
      'Cache-Control': 'no-store',
    });
    return res.end(), false;
  }
  if (!isAuthed(req)) {
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    return res.end('Add ?key=<yours> once.'), false;
  }
  return true;
}

// ---------- targets ----------
function encodeTarget(v) { return Buffer.from(v, 'utf8').toString('base64url'); }
function decodeTarget(v) {
  if (!/^[A-Za-z0-9_-]{1,12000}$/.test(v)) throw new Error('Invalid address.');
  const t = new URL(Buffer.from(v, 'base64url').toString('utf8'));
  if (!['http:', 'https:'].includes(t.protocol)) throw new Error('Only HTTP(S).');
  return t;
}
function proxyPath(t) { return `/p/${encodeTarget(t.origin)}${t.pathname}${t.search}`; }

function isPrivateAddress(a) {
  const f = net.isIP(a);
  if (f === 4) {
    const [x, y] = a.split('.').map(Number);
    return x === 0 || x === 10 || x === 127 || (x === 169 && y === 254)
      || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168) || x >= 224;
  }
  if (f === 6) return a === '::' || a === '::1' || a.startsWith('fc') || a.startsWith('fd') || a.startsWith('fe8');
  return true;
}
async function validatePublicTarget(t) {
  const h = t.hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) throw new Error('Local addr.');
  if (net.isIP(h)) { if (isPrivateAddress(h)) throw new Error('Private addr.'); return; }
  const ans = await lookup(h, { all: true, verbatim: true });
  if (!ans.length || ans.some(a => isPrivateAddress(a.address))) throw new Error('Did not resolve public.');
}

// ---------- rewriting ----------
function resolveLink(v, base) {
  const raw = v.trim();
  if (!raw || raw.startsWith('#') || /^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(raw)) return v;
  try {
    const r = new URL(raw, base);
    if (!['http:', 'https:'].includes(r.protocol)) return v;
    return proxyPath(r);
  } catch { return v; }
}
function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, v) => `url("${resolveLink(v, base)}")`)
    .replace(/@import\s+(?:url\()?\s*(['"])(.*?)\1\s*\)?/gi, (m, q, v) => `@import url("${resolveLink(v, base)}")`);
}

function rewriteHtml(html, target) {
  const attrs = ['href', 'src', 'action', 'formaction', 'poster', 'data', 'xlink:href'];
  const ap = new RegExp(`(\\b(?:${attrs.join('|')})\\s*=\\s*)(["'])(.*?)\\2`, 'gis');
  let out = html.replace(ap, (m, p, q, v) => `${p}${q}${resolveLink(v, target)}${q}`);
  out = out.replace(/<meta\b[^>]*http-equiv\s*=\s*(["'])?content-security-policy\1?[^>]*>/gi, '');
  // Let Unity's preload tags work; the proxy streams them correctly.
  // Remove preload links for the main asset to force a standard fetch through our shim
  out = out.replace(/<link\b[^>]*rel=["']preload["'][^>]*final\.pkg[^>]*>/gi, '');
  out = out.replace(/srcset\s*=\s*(["'])(.*?)\1/gis, (m, q, v) => {
    const items = v.split(',').map(item => {
      const parts = item.trim().split(/\s+/);
      if (parts[0]) parts[0] = resolveLink(parts[0], target);
      return parts.join(' ');
    });
    return `srcset=${q}${items.join(', ')}${q}`;
  });
  out = out.replace(/<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi, (m, a, css) => `<style${a}>${rewriteCss(css, target)}</style>`);
  out = out.replace(/\sstyle=(['"])(.*?)\1/gi, (m, q, css) => ` style=${q}${rewriteCss(css, target)}${q}`);

  // runtime: NO WebSocket monkey-patch. Everything else patched.
  const runtime = `<script>(function(){
    var TARGET_BASE = ${JSON.stringify(target.origin)};
    var TARGET_HOSTNAME = new URL(TARGET_BASE).hostname;
    var NATIVE_FETCH = window.fetch.bind(window);
    var NATIVE_BEACON = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;

    function encode(v){ return btoa(unescape(encodeURIComponent(v))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,''); }

    function proxify(value){
      if (typeof value !== 'string') value = String(value);
      if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(value)) return value;
      try {
        var current = new URL(value, TARGET_BASE);
        if (current.protocol !== 'http:' && current.protocol !== 'https:') return value;
        if (current.hostname.indexOf('.') < 0) return value;
        if (current.pathname.indexOf('/p/') === 0) return current.pathname + current.search;
        if (current.pathname.indexOf('/_ws/') === 0) return current.pathname + current.search;
        return '/p/' + encode(current.origin) + current.pathname + current.search;
      } catch (e) { return value; }
    }

    // fetch
    window.fetch = async function(input, init){
      var request = input instanceof Request ? input : new Request(input, init);
      var proxified = proxify(request.url);
      var opts = {
        method: request.method, headers: request.headers,
        mode: request.mode === 'navigate' ? 'cors' : request.mode,
        credentials: 'include',
        cache: request.cache, redirect: request.redirect,
        integrity: request.integrity, signal: request.signal
      };
      if (request.body && request.method !== 'GET' && request.method !== 'HEAD') {
        opts.body = await request.clone().arrayBuffer();
      }
      try {
        var res = await NATIVE_FETCH(proxified, opts);
        if (!request.url.startsWith('data:')) console.log('[fetch]', request.method, request.url, '->', res.status);
        return res;
      } catch (e) {
        console.log('[fetch-err]', request.method, request.url, e.message);
        throw e;
      }
    };

    // XHR
    var nativeOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url){
      var args = Array.prototype.slice.call(arguments);
      var original = String(url);
      args[1] = proxify(original);
      if (original !== args[1]) console.log('[xhr]', method, original, '->', args[1]);
      return nativeOpen.apply(this, args);
    };

    // sendBeacon
    if (NATIVE_BEACON) {
      navigator.sendBeacon = function(url, data){
        try { return NATIVE_BEACON(proxify(String(url)), data); }
        catch (e) { return NATIVE_BEACON(url, data); }
      };
    }

    // WebSocket — route through our /_ws/ proxy
    var NATIVE_WS = window.WebSocket;
    window.WebSocket = new Proxy(NATIVE_WS, {
      construct: function(target, args){
        if (args.length > 0 && args[0] != null) {
          var original = String(args[0]);
          try {
            var u = new URL(original, TARGET_BASE);
            var alreadyProxied = (u.hostname === location.hostname && u.pathname.indexOf('/_ws/') === 0);
            if (!alreadyProxied && (u.protocol === 'ws:' || u.protocol === 'wss:' || u.protocol === 'http:' || u.protocol === 'https:')) {
              var isSecure = u.protocol === 'wss:' || u.protocol === 'https:';
              var targetOrigin = (isSecure ? 'https:' : 'http:') + '//' + u.hostname + (u.port ? ':' + u.port : '');
              var wsScheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
              var sep = u.search ? '&' : '?';
              var proxified = wsScheme + '//' + location.host + '/_ws/' + encode(targetOrigin) + u.pathname + u.search + sep + 'o=' + encode(TARGET_BASE);
              console.log('[ws] ' + original + ' -> ' + proxified);
              args[0] = proxified;
            }
          } catch (e) { console.log('[ws] error ' + original + ': ' + e.message); }
        }
        return Reflect.construct(target, args);
      }
    });

    // Service worker register
    if (navigator.serviceWorker) {
      var nativeReg = navigator.serviceWorker.register;
      navigator.serviceWorker.register = function(scriptURL, opts){
        return nativeReg.call(this, proxify(String(scriptURL)), opts);
      };
    }

    var imgDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    console.log('[proxy] img.src descriptor:', imgDesc ? { hasGet: !!imgDesc.get, hasSet: !!imgDesc.set, configurable: imgDesc.configurable } : 'missing');
    console.log('[proxy] runtime installed target=' + TARGET_BASE);
  })();</script>`;

  if (/<head\b[^>]*>/i.test(out)) out = out.replace(/<head\b[^>]*>/i, h => `${h}${runtime}`);
  else out = runtime + out;
  return out;
}

// ---------- cookies ----------
// Note: cookies are scoped to Path=/ (not /p/<token>/) so they are also sent
// on /_ws/ WebSocket upgrades. Without this, session cookies set on the page
// are missing on the party socket and the server rejects the handshake.
function rewriteSetCookie(cookie, target) {
  let out = cookie.replace(/;\s*domain=[^;]*/i, '');
  out = out.replace(/;\s*path=[^;]*/i, '; Path=/');
  if (!/;\s*path=/i.test(out)) out += '; Path=/';
  if (/;\s*SameSite=(Lax|Strict)/i.test(out)) out = out.replace(/;\s*SameSite=(Lax|Strict)/i, '; SameSite=None');
  else if (!/;\s*SameSite=/i.test(out)) out += '; SameSite=None';
  if (!/;\s*Secure/i.test(out)) out += '; Secure';
  return out;
}

// ---------- request forwarding ----------
async function readRequestBody(req) {
  const chunks = []; let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_REQUEST_BYTES) throw new Error('Too large');
    chunks.push(c);
  }
  return size ? Buffer.concat(chunks) : undefined;
}

async function proxyRequest(req, res, target) {
  const started = Date.now();
  await validatePublicTarget(target);
  proxyHostTargets.set(String(req.headers.host || '').split(':')[0], target.origin);

  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (['host', 'connection', 'content-length', 'accept-encoding', 'origin', 'referer', 'cookie'].includes(lower)) continue;
    if (Array.isArray(value)) headers.set(name, value.join(', '));
    else headers.set(name, value);
  }
  const cookie = (req.headers.cookie || '').split(';').map(c => c.trim())
    .filter(c => c && !c.startsWith(COOKIE_NAME + '=')).join('; ');
  if (cookie) headers.set('cookie', cookie);
  
  // Force identity encoding so Content-Length matches the actual bytes sent.
  // Node's fetch decompresses gzip by default, which breaks the Content-Length.
  headers.set('accept-encoding', 'identity');
  if (req.headers.origin) headers.set('origin', target.origin);
  if (req.headers.referer) {
    try {
      const r = new URL(req.headers.referer);
      const m = r.pathname.match(/^\/p\/([A-Za-z0-9_-]+)/);
      if (m) headers.set('referer', decodeTarget(m[1]).href);
    } catch {}
  }

  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRequestBody(req);
  const upstream = await fetch(target, { method: req.method, headers, body, redirect: 'manual' });

  const out = new Headers(upstream.headers);
   for (const n of ['content-security-policy','content-security-policy-report-only','x-frame-options',
                   'cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy',
                   'permissions-policy','access-control-allow-origin','access-control-allow-credentials',
                   'content-encoding','transfer-encoding','connection','set-cookie','alt-svc']) {
    out.delete(n);
  }
  const ct = upstream.headers.get('content-type') || '';
  if (/text\/html|application\/xhtml\+xml/i.test(ct)) out.set('cache-control', 'no-store');

  const acao = req.headers.origin || '*';
  out.set('access-control-allow-origin', acao);
  out.set('access-control-allow-credentials', 'true');
  out.set('access-control-allow-methods', 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS');
  out.set('access-control-allow-headers', req.headers['access-control-request-headers'] || '*');
  out.set('access-control-expose-headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Type');
  out.set('referrer-policy', 'same-origin');

  const cookies = typeof upstream.headers.getSetCookie === 'function'
    ? upstream.headers.getSetCookie()
    : (upstream.headers.get('set-cookie') || '').split(/,(?=\s*[^;,]+=)/).filter(Boolean);
  const setCookie = cookies.map(c => rewriteSetCookie(c, target));

  const location = upstream.headers.get('location');
  if (location) { try { out.set('location', proxyPath(new URL(location, target))); } catch {} }

  const headerObj = {};
  for (const [k, v] of out.entries()) headerObj[k] = v;
  if (setCookie.length) headerObj['set-cookie'] = setCookie;

  if (/text\/html|application\/xhtml\+xml/i.test(ct)) {
    const html = rewriteHtml(await upstream.text(), target);
    headerObj['content-type'] = 'text/html; charset=utf-8';
    res.writeHead(upstream.status, headerObj);
    return res.end(html);
  }
  if (/text\/css/i.test(ct)) {
    const css = rewriteCss(await upstream.text(), target);
    headerObj['content-type'] = 'text/css; charset=utf-8';
    res.writeHead(upstream.status, headerObj);
    return res.end(css);
  }
  if (/application\/json/i.test(ct) || (ct.includes('text/plain') && target.hostname.includes('matchmaking'))) {
    const text = await upstream.text();
    console.log(`[json] ${target.hostname}${target.pathname.slice(0, 40)} (${text.length}B): ${text.slice(0, 300).replace(/\s+/g, ' ')}`);
    const originToken = Buffer.from(target.origin, 'utf8').toString('base64url');
    const wsScheme = (req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted) ? 'wss' : 'ws';
    const rewritten = text.replace(/(["'])wss?:\/\/[^"']+\1/gi, (match, q) => {
      const url = match.slice(1, -1);
      const encoded = Buffer.from(url.replace(/^wss:\/\//i, 'https://').replace(/^ws:\/\//i, 'http://')).toString('base64url');
      return `${q}${wsScheme}://${req.headers.host}/_ws/${encoded}?o=${originToken}${q}`;
    });
    headerObj['content-type'] = 'application/json; charset=utf-8';
    res.writeHead(upstream.status, headerObj);
    return res.end(rewritten);
  }

  // Stream the response to avoid memory buffering issues with large files
  const ds = Readable.fromWeb(upstream.body);
  res.writeHead(upstream.status, headerObj);
  ds.on('error', () => { if (!res.destroyed) res.destroy(); });
  res.on('close', () => { if (!res.writableFinished) ds.destroy(); });
  ds.pipe(res);
}

// ---------- WebSocket relay ----------
async function relayUpgrade(req, client, head, target, originOverride, sid) {
  if (client.parser) client.parser = null;
  client.setNoDelay(true);
  client.setKeepAlive(true, 30000);

  const secure = target.protocol === 'wss:';
  const port = Number(target.port) || (secure ? 443 : 80);
  const upstream = secure
    ? tls.connect({ host: target.hostname, port, servername: target.hostname })
    : net.connect({ host: target.hostname, port });

  upstream.once(secure ? 'secureConnect' : 'connect', () => {
    upstream.setNoDelay(true);
    upstream.setKeepAlive(true, 30000);
    const lines = [`${req.method} ${target.pathname}${target.search} HTTP/${req.httpVersion}`];
    let hasOrigin = false;
    for (const [name, value] of Object.entries(req.headers)) {
      const lower = name.toLowerCase();
      if (lower === 'host') { lines.push(`Host: ${target.host}`); continue; }
      if (lower === 'origin') { hasOrigin = true; lines.push(`Origin: ${originOverride || target.origin.replace(/^wss?:/i, 'https:')}`); continue; }
      if (lower === 'cookie') {
        const c = String(value).split(';').map(x => x.trim()).filter(x => x && !x.startsWith(COOKIE_NAME + '=')).join('; ');
        if (c) lines.push(`Cookie: ${c}`);
        continue;
      }
      if (lower === 'referer') continue;
      if (value) lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
    }
    if (!hasOrigin && originOverride) lines.push(`Origin: ${originOverride}`);
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head?.length) upstream.write(head);
    console.log(`[ws] dialing ${target.href} sid=${sid.slice(0, 8)}`);
    console.log(`[ws] outgoing: ${lines[0]} | Host: ${target.host} | Origin: ${originOverride || '(none)'}`);
    client.pipe(upstream);
  });

  let buf = Buffer.alloc(0);
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const end = buf.indexOf('\r\n\r\n');
    if (end < 0) return;
    const handshake = buf.subarray(0, end + 4).toString('latin1');
    const statusLine = handshake.split('\r\n')[0];
    if (!/^HTTP\/1\.[01] 101\b/m.test(handshake)) {
      console.log(`[ws] upstream rejected: ${statusLine} sid=${sid.slice(0, 8)}`);
      client.write(buf);
      client.end();
      upstream.destroy();
      return;
    }
    console.log(`[ws] upstream accepted: ${statusLine} sid=${sid.slice(0, 8)}`);
    client.write(buf);
    upstream.removeListener('data', onData);

    // Match IP capture: sniff party socket traffic
    if (target.hostname.startsWith('party.') || target.hostname.includes('.party.') || target.hostname.startsWith('ip_')) {
      const needle = Buffer.from([0xa2, 0x69, 0x70, 0xd9, 0x20]);
      let tail = Buffer.alloc(0);
      upstream.on('data', (c) => {
        const comb = Buffer.concat([tail, c]);
        let idx = 0;
        while ((idx = comb.indexOf(needle, idx)) !== -1) {
          const hex = comb.slice(idx + needle.length, idx + needle.length + 32).toString('ascii');
          if (/^[0-9a-f]{32}$/.test(hex) && originOverride) {
            lastMatchIpByTarget.set(`${sid}:${originOverride}`, hex);
            console.log(`[proxy] match ip captured ${hex.slice(0, 8)}... sid=${sid.slice(0, 8)}`);
          }
          idx += needle.length;
        }
        tail = comb.slice(-80);
      });
    }

    upstream.pipe(client);
  };
  upstream.on('data', onData);
  upstream.on('error', (e) => {
    console.log(`[ws] upstream error: ${e.message} sid=${sid.slice(0, 8)}`);
    client.destroy();
  });
  client.on('error', () => upstream.destroy());
}

function decrementWs(key) {
  wsCountByKey.set(key, Math.max(0, (wsCountByKey.get(key) || 1) - 1));
}

// ---------- HTTP server ----------
const server = http.createServer({ timeout: 0 }, async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': req.headers.origin || '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': '*',
      'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || '*',
    });
    return res.end();
  }
  if (!checkAuth(req, res)) return;

  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); } catch { return res.writeHead(400).end(); }

  if (local.pathname === '/favicon.ico') return res.writeHead(204).end();

  if (local.pathname.startsWith('/p/')) {
    let target;
    try {
      const m = local.pathname.match(/^\/p\/([A-Za-z0-9_-]+)(\/.*)?$/);
      if (!m) throw new Error('bad path');
      target = decodeTarget(m[1]);
      if (m[2] && m[2] !== '/') { target.pathname = m[2]; target.search = local.search; }
      else if (local.search) target.search = local.search;
      else if (m[2] === '/') target.pathname = '/';
    } catch (e) { return res.writeHead(400).end(e.message); }
    return proxyRequest(req, res, target).catch((e) => {
      if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Upstream failed: ' + e.message);
    });
  }

  if (req.method === 'GET' && local.pathname === '/') {
    try {
      const page = fs.readFileSync(PAGE_PATH, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(page);
    } catch { return res.writeHead(500).end('index.html missing'); }
  }

  // Fallback for Web Worker / relative requests (like final.pkg)
  let refererTarget = null;
  if (req.headers.referer) {
    try {
      const r = new URL(req.headers.referer);
      const m = r.pathname.match(/^\/p\/([A-Za-z0-9_-]+)/);
      if (m) refererTarget = decodeTarget(m[1]).origin;
    } catch {}
  }
  
  if (!refererTarget) {
    const host = String(req.headers.host || '').split(':')[0];
    refererTarget = proxyHostTargets.get(host);
  }

  if (refererTarget) {
    try {
      const target = new URL(local.pathname + local.search, refererTarget);
      console.log(`[fallback] ${local.pathname} -> ${target.href} (referer: ${req.headers.referer || 'none'})`);
      return proxyRequest(req, res, target).catch((e) => {
        if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('Upstream failed: ' + e.message);
      });
    } catch (e) {
      return res.writeHead(400).end(e.message);
    }
  }

  res.writeHead(404).end('Not found');
});

server.on('upgrade', async (req, client, head) => {
  if (!isAuthed(req)) {
    client.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }
  const sid = sessionId(req);
  const key = `proxy:${sid}`;
  if ((wsCountByKey.get(key) || 0) >= MAX_WS_PER_SESSION) {
    client.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }

  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); } catch { return client.destroy(); }

  let target, originOverride;
  try {
    const explicit = local.pathname.match(/^\/_ws\/([A-Za-z0-9_-]+)(\/.*)?$/);
    if (explicit) {
      target = decodeTarget(explicit[1]);
      if (explicit[2]) target.pathname = explicit[2];
      target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
      const o = local.searchParams.get('o');
      if (o) try { originOverride = Buffer.from(o, 'base64url').toString('utf8'); } catch {}
      local.searchParams.delete('o');
      if (!target.search && local.searchParams.toString()) target.search = '?' + local.searchParams.toString();
      await validatePublicTarget(target);
      console.log(`[ws] explicit -> ${target.href} origin=${originOverride || '(none)'} sid=${sid.slice(0, 8)}`);
    } else {
      // Relative /ws upgrade. Find the target via Referer.
      let pageTarget = null;
      const ref = req.headers.referer;
      if (ref) {
        try {
          const r = new URL(ref);
          const m = r.pathname.match(/^\/p\/([A-Za-z0-9_-]+)/);
          if (m) pageTarget = decodeTarget(m[1]);
        } catch {}
      }
      if (!pageTarget) {
        const host = String(req.headers.host || '').split(':')[0];
        const fallback = proxyHostTargets.get(host);
        if (fallback) pageTarget = new URL(fallback);
      }
      if (!pageTarget) throw new Error('No target for WS upgrade.');

      const matchKey = `${sid}:${pageTarget.origin}`;
      const matchIp = lastMatchIpByTarget.get(matchKey);
      const wsHost = matchIp
        ? `ip_${matchIp}.party.${pageTarget.hostname}`
        : `party.${pageTarget.hostname}`;
      const search = local.search && !local.searchParams.has('__k') ? local.search : '';
      target = new URL(`wss://${wsHost}${local.pathname}${search}`);
      originOverride = pageTarget.origin;
      await validatePublicTarget(target);
      console.log(`[ws] fallback -> ${target.href} origin=${originOverride} sid=${sid.slice(0, 8)}`);
    }
  } catch (e) {
    console.log(`[ws] rejected: ${e.message} sid=${sid.slice(0, 8)}`);
    client.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }

  wsCountByKey.set(key, (wsCountByKey.get(key) || 0) + 1);
  let released = false;
  const release = () => { if (!released) { released = true; decrementWs(key); } };
  client.once('close', release);

  await relayUpgrade(req, client, head, target, originOverride, sid);
});

server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Proxy listening on ${BIND_ADDRESS}:${PORT}`);
  if (!VALID_KEYS.size) console.warn('No valid keys — every request will 401. Fix users.json.');
});