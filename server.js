const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const zlib = require('node:zlib');
const { lookup } = require('node:dns/promises');
const { Readable } = require('node:stream');

const HOST = '127.0.0.1';
const BIND_ADDRESS = process.env.BIND_ADDRESS || '0.0.0.0';
const PORT = Number(process.env.PORT || 8787);
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
const PAGE_PATH = path.join(__dirname, 'index.html');
const USERS_PATH = path.join(__dirname, 'users.json');
const COOKIE_NAME = '__proxy_access';
const LOG_LIMIT = 3000;

// Bodies sent to these hosts get captured (up to 8 KB) so we can see what the
// game reports when it says "couldn't load game".
const BODY_CAPTURE_HOST = /error|report|crash|sentry|bugsnag|rollbar|telemetry/i;

// ---------- Logging ----------

let logSeq = 0;
const recentLogs = [];

function recordLog(entry) {
  entry.id = ++logSeq;
  entry.ts = new Date().toISOString();
  recentLogs.push(entry);
  if (recentLogs.length > LOG_LIMIT) recentLogs.shift();
  try {
    if (entry.kind === 'client') {
      console.log(`[client:${entry.level || 'info'}] ${entry.msg || ''} ${entry.extra ? JSON.stringify(entry.extra) : ''}`);
    } else {
      console.log(`[${entry.kind || 'info'}] ${JSON.stringify(entry)}`);
    }
  } catch { /* ignore */ }
}

// ---------- Users / auth ----------

let VALID_KEYS = new Set();
try {
  const raw = JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
  const list = Array.isArray(raw.keys) ? raw.keys : [];
  VALID_KEYS = new Set(list.filter(u => u && u.active !== false).map(u => u.key));
  console.log(`Loaded ${VALID_KEYS.size} active key(s) from users.json`);
} catch (e) {
  console.error('Failed to load users.json:', e.message);
}

function keyFromCookie(header) {
  const m = (header || '').match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}

function isAuthed(req) {
  const key = keyFromCookie(req.headers.cookie);
  return !!(key && VALID_KEYS.has(key));
}

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
    var TARGET_BASE = ${JSON.stringify(target.origin)};
    var TARGET_HOSTNAME = new URL(TARGET_BASE).hostname;
    var NATIVE_FETCH = window.fetch.bind(window);
    var NATIVE_BEACON = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;

    // ---- client-side logging ----
    var LOG_ENDPOINT = '/__log';
    var LOG_BATCH = 25;
    var logBuffer = [];

    function shipLogs(useBeacon) {
      if (!logBuffer.length) return;
      var payload = JSON.stringify(logBuffer.splice(0, logBuffer.length));
      try {
        if (useBeacon && NATIVE_BEACON) NATIVE_BEACON(LOG_ENDPOINT, payload);
        else NATIVE_FETCH(LOG_ENDPOINT, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          credentials: 'include', body: payload, keepalive: true
        }).catch(function(){});
      } catch (e) {}
    }

    function plog(level, msg, extra) {
      var entry = { level: level, msg: String(msg), page: location.pathname, t: Date.now() };
      if (extra) for (var k in extra) { try { entry[k] = extra[k]; } catch(e){} }
      logBuffer.push(entry);
      try { console.log('[proxy-log]', level, msg, extra || ''); } catch(e){}
      if (logBuffer.length >= LOG_BATCH) shipLogs(false);
    }

    setInterval(function(){ shipLogs(false); }, 3000);
    window.addEventListener('pagehide', function(){ shipLogs(true); });
    window.addEventListener('beforeunload', function(){ shipLogs(true); });

    window.addEventListener('error', function(e){
      try {
        if (e && e.target && e.target !== window && e.target.tagName) {
          plog('error', 'resource-fail', { tag: e.target.tagName, src: String(e.target.src || e.target.href || '') });
        } else {
          plog('error', 'script-error', {
            message: e && e.message, filename: e && e.filename,
            line: e && e.lineno, col: e && e.colno,
            stack: e && e.error && e.error.stack
          });
        }
      } catch (x) {}
    }, true);

    window.addEventListener('unhandledrejection', function(e){
      try {
        var r = e && e.reason;
        plog('error', 'unhandled-rejection', { message: r && (r.message || String(r)), stack: r && r.stack });
      } catch (x) {}
    });

    // ---- capability snapshot (once, at startup) ----
    (function reportCaps(){
      try {
        var caps = {
          crossOriginIsolated: window.crossOriginIsolated === true,
          sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
          atomics: typeof Atomics !== 'undefined',
          wasm: typeof WebAssembly === 'object' && typeof WebAssembly.instantiate === 'function',
          baseURI: document.baseURI,
          href: location.href,
          origin: location.origin,
          hostname: location.hostname,
          top: window === window.top,
          inIframe: window.top !== window.self
        };
        try {
          var c = document.createElement('canvas');
          caps.webgl2 = !!c.getContext('webgl2');
          caps.webgl = !!(c.getContext('webgl') || c.getContext('experimental-webgl'));
        } catch (e) { caps.webglErr = e.message; }
        plog('info', 'capabilities', caps);
      } catch (e) { plog('error', 'capability check failed', { message: e.message }); }
    })();

    // ---- URL proxify ----
    function encode(value) {
      return btoa(unescape(encodeURIComponent(value))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
    }

    function proxify(value) {
      if (typeof value !== 'string') value = String(value);
      if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(value)) return value;
      try {
        var current = new URL(value, TARGET_BASE);
        if (current.protocol !== 'http:' && current.protocol !== 'https:') return value;
        if (current.hostname.indexOf('.') < 0) return value;
        if (current.pathname.indexOf('/p/') === 0) return current.pathname + current.search;
        if (current.pathname.indexOf('/__') === 0) return current.pathname + current.search;
        if (current.pathname.indexOf('/_ws/') === 0) return current.pathname + current.search;
        if (current.hostname === window.location.hostname) {
          return '/p/' + encode(TARGET_BASE) + current.pathname + current.search;
        }
        return '/p/' + encode(current.origin) + current.pathname + current.search;
      } catch (e) { return value; }
    }

    // ---- fetch ----
    window.fetch = function(input, init) {
      var request;
      try { request = input instanceof Request ? input : new Request(input, init); }
      catch (e) { plog('error', 'fetch construct failed', { message: e.message }); return Promise.reject(e); }
      var method = request.method || 'GET';
      var proxified = proxify(request.url);
      var started = (window.performance && performance.now()) || Date.now();
      var bodyPromise = Promise.resolve(undefined);
      if (request.body && method !== 'GET' && method !== 'HEAD') {
        try { bodyPromise = request.clone().arrayBuffer(); } catch (e) { bodyPromise = Promise.resolve(undefined); }
      }
      return bodyPromise.then(function(bodyBuf){
        var opts = {
          method: method, headers: request.headers,
          mode: request.mode === 'navigate' ? 'cors' : (request.mode || 'cors'),
          credentials: 'include', cache: request.cache, redirect: request.redirect,
          integrity: request.integrity, signal: request.signal
        };
        if (bodyBuf) opts.body = bodyBuf;
        return NATIVE_FETCH(proxified, opts).then(function(resp){
          var ms = Math.round(((window.performance && performance.now()) || Date.now()) - started);
          plog(resp.ok ? 'info' : 'error', method + ' ' + request.url + ' -> ' + resp.status + ' (' + ms + 'ms)');
          return resp;
        }, function(err){
          var ms = Math.round(((window.performance && performance.now()) || Date.now()) - started);
          plog('error', method + ' ' + request.url + ' FAILED after ' + ms + 'ms: ' + (err && err.message));
          throw err;
        });
      });
    };

    // ---- XHR ----
    var nativeOpen = XMLHttpRequest.prototype.open;
    var nativeSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__proxyUrl = String(url);
      var args = Array.prototype.slice.call(arguments);
      args[1] = proxify(String(url));
      return nativeOpen.apply(this, args);
    };
    XMLHttpRequest.prototype.send = function(body) {
      var xhr = this;
      var started = (window.performance && performance.now()) || Date.now();
      xhr.addEventListener('loadend', function(){
        var ms = Math.round(((window.performance && performance.now()) || Date.now()) - started);
        var ok = xhr.status >= 200 && xhr.status < 400;
        plog(ok ? 'info' : 'error', 'XHR ' + (xhr.__proxyUrl || '') + ' -> ' + xhr.status + ' (' + ms + 'ms)');
      });
      return nativeSend.call(xhr, body);
    };

    // ---- WebSocket ----
    var NativeWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      var newUrl = String(url);
      try {
        if (newUrl.indexOf('/_ws/') === 0) return new NativeWebSocket(newUrl, protocols);
        var wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        var resolved;
        if (newUrl.indexOf('ws://') === 0 || newUrl.indexOf('wss://') === 0) resolved = new URL(newUrl);
        else if (newUrl.indexOf('//') === 0) resolved = new URL(wsProto + newUrl);
        else if (newUrl.charAt(0) === '/') resolved = new URL(wsProto + '//party.' + TARGET_HOSTNAME + newUrl);
        else return new NativeWebSocket(newUrl, protocols);

        var finalUrl;
        if (resolved.hostname === window.location.hostname) {
          finalUrl = wsProto + '//party.' + TARGET_HOSTNAME + resolved.pathname + resolved.search;
        } else {
          finalUrl = resolved.origin + resolved.pathname + resolved.search;
        }
        newUrl = wsProto + '//' + window.location.host + '/_ws/' + encode(finalUrl);
        plog('info', 'WS ' + url + ' -> ' + newUrl);
      } catch (e) { plog('error', 'WS rewrite failed for ' + url + ': ' + (e && e.message)); }
      var sock = new NativeWebSocket(newUrl, protocols);
      sock.addEventListener('open', function(){ plog('info', 'WS open ' + newUrl); });
      sock.addEventListener('error', function(){ plog('error', 'WS error ' + newUrl); });
      sock.addEventListener('close', function(ev){ plog('info', 'WS close ' + newUrl + ' code=' + (ev && ev.code)); });
      return sock;
    };
    window.WebSocket.prototype = NativeWebSocket.prototype;
    window.WebSocket.CONNECTING = NativeWebSocket.CONNECTING;
    window.WebSocket.OPEN = NativeWebSocket.OPEN;
    window.WebSocket.CLOSING = NativeWebSocket.CLOSING;
    window.WebSocket.CLOSED = NativeWebSocket.CLOSED;

    // ---- sendBeacon ----
    if (NATIVE_BEACON) {
      navigator.sendBeacon = function(url, data) {
        try {
          var p = proxify(String(url));
          if (p.indexOf('/__') !== 0) plog('info', 'beacon ' + url + ' -> ' + p);
          return NATIVE_BEACON(p, data);
        } catch (e) { return NATIVE_BEACON(url, data); }
      };
    }

    // ---- Worker (with error listener) ----
    if (window.Worker) {
      var NativeWorker = window.Worker;
      window.Worker = function(url, opts) {
        plog('info', 'Worker create ' + url);
        var w;
        try { w = new NativeWorker(url, opts); }
        catch (e) { plog('error', 'Worker construct failed ' + url + ': ' + (e && e.message)); throw e; }
        w.addEventListener('error', function(ev){
          plog('error', 'Worker error ' + url, {
            message: ev && ev.message, filename: ev && ev.filename, lineno: ev && ev.lineno
          });
        });
        return w;
      };
      window.Worker.prototype = NativeWorker.prototype;
    }

    // ---- Service worker ----
    if (navigator.serviceWorker) {
      var nativeRegister = navigator.serviceWorker.register;
      navigator.serviceWorker.register = function(scriptURL, options) {
        var p = proxify(String(scriptURL));
        plog('info', 'SW register ' + scriptURL + ' -> ' + p);
        return nativeRegister.call(this, p, options);
      };
    }

    // ---- createElement ----
    var originalCreateElement = document.createElement.bind(document);
    document.createElement = function(tagName) {
      var el = originalCreateElement(tagName);
      if (tagName && (tagName.toLowerCase() === 'script' || tagName.toLowerCase() === 'link' || tagName.toLowerCase() === 'img')) {
        var nativeSetAttribute = el.setAttribute;
        el.setAttribute = function(name, value) {
          var lower = String(name).toLowerCase();
          if (lower === 'src' || lower === 'href') value = proxify(String(value));
          return nativeSetAttribute.call(el, name, value);
        };
      }
      return el;
    };

    // ---- DOM property patch ----
    function patchUrlProperty(proto, prop) {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.get || !d.set || !d.configurable) return;
      Object.defineProperty(proto, prop, {
        configurable: true, enumerable: d.enumerable,
        get: function(){ return d.get.call(this); },
        set: function(v){ d.set.call(this, typeof v === 'string' ? proxify(v) : v); }
      });
    }
    patchUrlProperty(HTMLIFrameElement.prototype, 'src');
    patchUrlProperty(HTMLScriptElement.prototype, 'src');
    patchUrlProperty(HTMLImageElement.prototype, 'src');
    patchUrlProperty(HTMLLinkElement.prototype, 'href');
    patchUrlProperty(HTMLMediaElement.prototype, 'src');
    patchUrlProperty(HTMLSourceElement.prototype, 'src');
    patchUrlProperty(HTMLVideoElement.prototype, 'poster');

    plog('info', 'runtime installed', { target: TARGET_BASE, href: location.href });
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
  return header.replace(/;\s*domain=[^;]*/gi, '');
}

function maybeLogErrorReport(target, req, body) {
  if (!body || body.length > 50_000) return;
  if (!BODY_CAPTURE_HOST.test(target.hostname)) return;
  let text = '';
  const enc = String(req.headers['content-encoding'] || '').toLowerCase();
  try {
    if (enc === 'gzip') text = zlib.gunzipSync(body).toString('utf8');
    else if (enc === 'deflate') text = zlib.inflateSync(body).toString('utf8');
    else if (enc === 'br') text = zlib.brotliDecompressSync(body).toString('utf8');
    else text = body.toString('utf8');
  } catch (e) { text = '<decode failed: ' + e.message + '>'; }
  recordLog({
    kind: 'error-report',
    target: target.href,
    ctype: req.headers['content-type'] || '',
    encoding: enc || null,
    len: body.length,
    body: text.slice(0, 8000),
  });
}

async function proxyRequest(req, res, target) {
  const started = Date.now();
  res.on('finish', () => {
    recordLog({
      kind: 'server',
      method: req.method,
      target: target.href,
      status: res.statusCode,
      ms: Date.now() - started,
      ctype: String(res.getHeader('content-type') || ''),
    });
  });

  try { await validatePublicTarget(target); }
  catch (e) {
    recordLog({ kind: 'server-error', target: target.href, error: 'validatePublicTarget: ' + e.message });
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
  if (body) maybeLogErrorReport(target, req, body);

  let upstream;
  try { upstream = await fetch(target, { method: req.method, headers, body, redirect: 'manual' }); }
  catch (e) {
    recordLog({ kind: 'server-error', target: target.href, error: 'fetch upstream: ' + e.message });
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Upstream fetch failed: ' + e.message);
  }

  const outHeaders = new Headers(upstream.headers);
  for (const name of ['content-security-policy', 'x-frame-options', 'content-encoding',
                      'content-length', 'transfer-encoding', 'connection', 'set-cookie']) {
    outHeaders.delete(name);
  }

  if (typeof upstream.headers.getSetCookie === 'function') {
    for (const c of upstream.headers.getSetCookie()) outHeaders.append('set-cookie', rewriteSetCookie(c));
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

  const headerObj = {};
  for (const [k, v] of outHeaders.entries()) {
    if (k.toLowerCase() === 'set-cookie') (headerObj['set-cookie'] ||= []).push(v);
    else headerObj[k] = v;
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

  const started = Date.now();
  recordLog({ kind: 'ws', method: 'UPGRADE', target: target.href });

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
    const statusLine = responseBuffer.slice(0, responseBuffer.indexOf('\r\n')).toString();
    recordLog({ kind: 'ws-open', target: target.href, status: statusLine, ms: Date.now() - started });
    client.write(responseBuffer);
    upstream.removeListener('data', onUpstreamData);
    upstream.pipe(client);
  };
  upstream.on('data', onUpstreamData);
  upstream.on('error', (e) => { recordLog({ kind: 'ws-error', target: target.href, error: e.message }); client.destroy(); });
  client.on('error', () => upstream.destroy());
}

// ---------- HTTP server ----------

const server = http.createServer({ timeout: 0 }, async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': '*',
    });
    return res.end();
  }

  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); }
  catch { return res.writeHead(400).end(); }

  if (local.pathname === '/favicon.ico') return res.writeHead(204).end();
  if (!checkAuth(req, res)) return;

  // ---- Log ingestion ----
  if (req.method === 'POST' && local.pathname === '/__log') {
    let body = '';
    try {
      for await (const chunk of req) {
        body += chunk.toString('utf8');
        if (body.length > 500_000) break;
      }
      const arr = JSON.parse(body);
      if (Array.isArray(arr)) {
        for (const e of arr) {
          const { level, msg, page, t, ...extra } = e || {};
          recordLog({ kind: 'client', level, msg, page, clientT: t, extra });
        }
      }
    } catch (e) {
      recordLog({ kind: 'client-error', error: e.message });
    }
    res.writeHead(204).end();
    return;
  }

  // ---- Log retrieval ----
  if (req.method === 'GET' && local.pathname === '/__logs') {
    const after = Number(local.searchParams.get('after') || 0);
    const fmt = local.searchParams.get('format') || 'json';
    const items = recentLogs.filter(e => e.id > after);
    if (fmt === 'txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(items.map(e => JSON.stringify(e)).join('\n') + '\n');
    }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify(items));
  }

  // ---- Proxied ----
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
      recordLog({ kind: 'server-error', path: local.pathname, error: e.message });
      return res.writeHead(400).end(e.message);
    }
    return proxyRequest(req, res, target);
  }

  // ---- Launcher ----
  if (req.method === 'GET' && local.pathname === '/') {
    let page;
    try { page = fs.readFileSync(PAGE_PATH, 'utf8'); }
    catch { return res.writeHead(500).end('index.html missing'); }
    page = page.replaceAll('__PROXY_PORT__', String(PORT));
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'credentialless',
    });
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
    recordLog({ kind: 'ws-error', path: local.pathname, error: e.message });
    client.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    return client.destroy();
  }
  await relayUpgrade(req, client, head, target);
});

server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Proxy listening on ${BIND_ADDRESS}:${PORT}`);
  if (!VALID_KEYS.size) console.warn('⚠️  No valid keys — every request will be rejected. Fix users.json.');
});