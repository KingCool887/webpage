const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { lookup } = require('node:dns/promises');
const { Readable } = require('node:stream');

const HOST = '127.0.0.1';
const BIND_ADDRESS = process.env.BIND_ADDRESS || '0.0.0.0';
const PORT = Number(process.env.PORT || 8787);
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

const XOR_KEY = "GhostProxy2026";
const MAX_WS_PER_SESSION = 20;

const lastMatchIpByPageHost = new Map();
const sessions = new Map();
const users = new Map();

// --- Load Users from users.json ---
function loadUsers() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8');
    const parsed = JSON.parse(data);
    for (const user of parsed.keys) {
      if (user.active) users.set(user.key, user.name);
    }
    console.log(`Loaded ${users.size} active keys.`);
  } catch (error) {
    console.error('CRITICAL: Could not load users.json. All users will be rejected.', error.message);
  }
}
loadUsers();

// --- XOR Obfuscation ---
function encodeTarget(value) {
  const str = String(value);
  let bin = "";
  for (let i = 0; i < str.length; i++) {
    bin += String.fromCharCode(str.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
  }
  return Buffer.from(bin, 'binary').toString('base64url');
}

function decodeTarget(value) {
  if (!/^[A-Za-z0-9_-]{1,12000}$/.test(value)) throw new Error('Invalid proxy address.');
  const bin = Buffer.from(value, 'base64url').toString('binary');
  let str = "";
  for (let i = 0; i < bin.length; i++) {
    str += String.fromCharCode(bin.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
  }
  const target = new URL(str);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS addresses are supported.');
  return target;
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(Array.isArray(xff) ? xff[0] : xff).split(',')[0].trim();
  return req.socket.remoteAddress || '';
}

function createSession(token, name, ip) {
  sessions.set(token, { token, name, ip, expires: Date.now() + SESSION_TTL_MS, wsCount: 0 });
}

function authenticateProxy(req, parsedPath) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)__pv_proxy=([^;]+)/);
  if (match) {
    const session = sessions.get(match[1]);
    if (session && session.expires > Date.now()) return session;
  }
  return null;
}

function sendUnauthorized(res) {
  res.writeHead(401, { 'Content-Type': 'text/plain' });
  res.end('Authentication required.');
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  if (family === 6) return address === '::' || address === '::1' || address.startsWith('fc') || address.startsWith('fd') || address.startsWith('fe8');
  return true;
}

async function validatePublicTarget(target) {
  const hostname = target.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) throw new Error('Local addresses not supported.');
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new Error('Private addresses not supported.');
    return;
  }
  try {
    const answers = await lookup(hostname, { all: true, verbatim: true });
    if (!answers.length || answers.some((answer) => isPrivateAddress(answer.address))) throw new Error('Did not resolve to public.');
  } catch (error) { throw error; }
}

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
    const XOR_KEY = "${XOR_KEY}";
    
    const encode = (str) => {
      let bin = "";
      for (let i = 0; i < str.length; i++) {
        bin += String.fromCharCode(str.charCodeAt(i) ^ XOR_KEY.charCodeAt(i % XOR_KEY.length));
      }
      return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    };

    const proxify = (value) => {
      if (typeof value !== 'string') value = String(value);
      if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(value)) return value;
      try {
        let current = new URL(value, TARGET_BASE);
        if (!['http:','https:'].includes(current.protocol)) return value;
        if (!current.hostname.includes('.')) return value;
        
        // Prevent double-proxying
        if (current.pathname.startsWith('/p/') || current.pathname.startsWith('/_ws/')) return current.pathname + current.search;
        if (current.hostname === window.location.hostname) return current.pathname + current.search;

        return '/p/' + encode(current.origin) + current.pathname + current.search;
      } catch { return value; }
    };
    
    // 1. Intercept Fetch and XHR (Force Cookies for final.pkg)
    const originalFetch = window.fetch.bind(window);
    window.fetch = async function(input, init){
      const request = input instanceof Request ? input : new Request(input, init);
      const proxified = proxify(request.url);
      const options = {
        method: request.method,
        headers: request.headers,
        mode: request.mode === 'navigate' ? 'cors' : request.mode,
        credentials: 'include', // FORCES COOKIE
        cache: request.cache,
        redirect: request.redirect,
        integrity: request.integrity,
        signal: request.signal,
      };
      if (request.body && !['GET', 'HEAD'].includes(request.method)) {
        const body = await request.clone().arrayBuffer();
        options.body = body;
      }
      return originalFetch(proxified, options);
    };
    
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest){ return originalOpen.call(this, method, proxify(String(url)), ...rest); };

    // 2. Intercept WebSockets (Fix Matchmaking)
    const NativeWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      let newUrl = url;
      try {
        if (url.startsWith('ws://') || url.startsWith('wss://')) {
          const urlObj = new URL(url);
          if (urlObj.hostname !== window.location.hostname) {
            const targetOrigin = urlObj.origin.replace(/^wss?:/i, 'https://');
            newUrl = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + 
                     window.location.host + 
                     '/_ws/' + 
                     encode(targetOrigin + urlObj.pathname + urlObj.search);
          }
        }
      } catch (e) {}
      return new NativeWebSocket(newUrl, protocols);
    };
    window.WebSocket.prototype = NativeWebSocket.prototype;
    window.WebSocket.CONNECTING = NativeWebSocket.CONNECTING;
    window.WebSocket.OPEN = NativeWebSocket.OPEN;
    window.WebSocket.CLOSING = NativeWebSocket.CLOSING;
    window.WebSocket.CLOSED = NativeWebSocket.CLOSED;

    // 3. Patch DOM URLs
    const patchUrlProperty = (prototype, property) => {
      const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
      if (!descriptor || !descriptor.get || !descriptor.set || !descriptor.configurable) return;
      Object.defineProperty(prototype, property, {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        get(){ return descriptor.get.call(this); },
        set(value){ descriptor.set.call(this, typeof value === 'string' ? proxify(value) : value); }
      });
    };
    patchUrlProperty(HTMLIFrameElement.prototype, 'src');
    patchUrlProperty(HTMLScriptElement.prototype, 'src');
    patchUrlProperty(HTMLImageElement.prototype, 'src');
    patchUrlProperty(HTMLLinkElement.prototype, 'href');
    patchUrlProperty(HTMLAnchorElement.prototype, 'href');
    patchUrlProperty(HTMLSourceElement.prototype, 'src');
    patchUrlProperty(HTMLMediaElement.prototype, 'src');
    patchUrlProperty(HTMLVideoElement.prototype, 'poster');
    patchUrlProperty(HTMLFormElement.prototype, 'action');
  })();</script>`;
  
  if (/<head\b[^>]*>/i.test(rewritten)) rewritten = rewritten.replace(/<head\b[^>]*>/i, (head) => `${head}${runtime}`);
  else rewritten = runtime + rewritten;
  return rewritten;
}

function responseCookies(response, target) {
  const cookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
  const prefix = `/p/${encodeTarget(target.origin)}`;
  return cookies.map((cookie) => {
    let out = cookie.replace(/;\s*domain=[^;]*/i, '');
    out = out.replace(/;\s*path=([^;]*)/i, (m, p) => {
      const raw = (p.trim() || '/');
      const norm = raw.startsWith('/') ? raw : `/${raw}`;
      return `; Path=${prefix}${norm === '/' ? '' : norm}`;
    });
    if (/;\s*SameSite=(Lax|Strict)/i.test(out)) out = out.replace(/;\s*SameSite=(Lax|Strict)/i, '; SameSite=None');
    else if (!/;\s*SameSite=/i.test(out)) out += '; SameSite=None';
    if (!/;\s*Secure/i.test(out)) out += '; Secure';
    return out;
  });
}

async function readRequestBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > MAX_REQUEST_BYTES) throw new Error('Too large'); chunks.push(chunk); }
  return size ? Buffer.concat(chunks) : undefined;
}

async function proxyRequest(req, res, target, session) {
  await validatePublicTarget(target);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (['host', 'connection', 'content-length', 'origin', 'referer', 'cookie'].includes(lower)) continue;
    if (Array.isArray(value)) headers.set(name, value.join(', '));
    else headers.set(name, value);
  }
  const cookie = req.headers.cookie || '';
  const cleanCookie = cookie.split(';').map(c => c.trim()).filter(c => c && !c.startsWith('__pv_')).join('; ');
  if (cleanCookie) headers.set('cookie', cleanCookie);
  if (req.headers.origin) headers.set('origin', target.origin);

  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRequestBody(req);
  const upstream = await fetch(target, { method: req.method, headers, body, redirect: 'manual' });
  
  const outHeaders = new Headers(upstream.headers);
  for (const name of ['content-security-policy', 'x-frame-options', 'content-encoding', 'content-length', 'transfer-encoding', 'connection']) {
    outHeaders.delete(name);
  }
  outHeaders.set('referrer-policy', 'same-origin');
  outHeaders.set('access-control-allow-origin', req.headers.origin || '*');
  outHeaders.set('access-control-allow-credentials', 'true');
  
  const cookies = responseCookies(upstream, target);
  outHeaders.delete('set-cookie');

  const location = upstream.headers.get('location');
  if (location) {
    try { outHeaders.set('location', proxyPath(new URL(location, target))); } catch {}
  }

  const contentType = upstream.headers.get('content-type') || '';
  if (/text\/html/i.test(contentType)) {
    const html = rewriteHtml(await upstream.text(), target);
    outHeaders.set('content-type', 'text/html; charset=utf-8');
    res.writeHead(upstream.status, { ...Object.fromEntries(outHeaders), ...(cookies.length ? { 'set-cookie': cookies } : {}) });
    return res.end(html);
  }
  if (/text\/css/i.test(contentType)) {
    const css = rewriteCss(await upstream.text(), target);
    outHeaders.set('content-type', 'text/css; charset=utf-8');
    res.writeHead(upstream.status, { ...Object.fromEntries(outHeaders), ...(cookies.length ? { 'set-cookie': cookies } : {}) });
    return res.end(css);
  }

  res.writeHead(upstream.status, { ...Object.fromEntries(outHeaders), ...(cookies.length ? { 'set-cookie': cookies } : {}) });
  if (!upstream.body || req.method === 'HEAD') return res.end();
  Readable.fromWeb(upstream.body).pipe(res);
}

// --- Single Server ---
const server = http.createServer({ timeout: 0 }, async (req, res) => {
  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); } catch { return res.writeHead(400).end(); }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': req.headers.origin || '*', 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' });
    return res.end();
  }

  // Auth Endpoint
  if (req.method === 'POST' && local.pathname === '/api/auth') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { key } = JSON.parse(body);
        const name = users.get(key);
        const ip = getClientIp(req);
        
        if (name) {
          const token = crypto.randomBytes(32).toString('base64url');
          createSession(token, name, ip);
          console.log(`[AUTH] User "${name}" logged in from IP ${ip}.`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ token }));
        } else {
          console.log(`[AUTH FAILED] Invalid key attempt from IP ${ip}.`);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid access key.' }));
        }
      } catch (e) {
        res.writeHead(400).end();
      }
    });
    return;
  }

  if (local.pathname.startsWith('/p/')) {
    const auth = authenticateProxy(req, local);
    if (!auth) return sendUnauthorized(res);

    if (local.searchParams.has('__k')) {
      const cleanUrl = new URL(req.url, `http://${HOST}:${PORT}`);
      cleanUrl.searchParams.delete('__k');
      res.writeHead(302, {
        'Location': cleanUrl.pathname + cleanUrl.search,
        'Set-Cookie': `__pv_proxy=${auth.token}; HttpOnly; SameSite=None; Secure; Path=/; Max-Age=86400`,
        'Cache-Control': 'no-store',
      });
      return res.end();
    }

    let target;
    try {
      const match = local.pathname.match(/^\/p\/([A-Za-z0-9_-]+)(\/.*)?$/);
      if (!match) throw new Error('Invalid path');
      target = decodeTarget(match[1]);
      if (match[2] && match[2] !== '/') { target.pathname = match[2]; target.search = local.search; }
      else if (local.search) target.search = local.search;
      else if (match[2] === '/') target.pathname = '/';
    } catch (e) { return res.writeHead(400).end(e.message); }

    return proxyRequest(req, res, target, auth);
  }

  return res.writeHead(404).end('Not found');
});

async function relayUpgrade(req, client, head, target, originOverride, sessionId) {
  const secure = target.protocol === 'wss:';
  const port = Number(target.port) || (secure ? 443 : 80);
  const upstream = secure ? tls.connect({ host: target.hostname, port, servername: target.hostname }) : net.connect({ host: target.hostname, port });

  upstream.once(secure ? 'secureConnect' : 'connect', () => {
    const lines = [`${req.method} ${target.pathname}${target.search} HTTP/${req.httpVersion}`];
    let hasOrigin = false;
    for (const [name, value] of Object.entries(req.headers)) {
      const lower = name.toLowerCase();
      if (lower === 'host') lines.push(`Host: ${target.host}`);
      else if (lower === 'origin') { hasOrigin = true; lines.push(`Origin: ${originOverride || target.origin}`); }
      else if (lower !== 'cookie' && value) lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
    }
    if (!hasOrigin && originOverride) lines.push(`Origin: ${originOverride}`);
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head?.length) upstream.write(head);
    client.pipe(upstream);
  });

  let responseBuffer = Buffer.alloc(0);
  const onUpstreamData = (chunk) => {
    responseBuffer = Buffer.concat([responseBuffer, chunk]);
    const end = responseBuffer.indexOf('\r\n\r\n');
    if (end < 0) return;
    const handshake = responseBuffer.subarray(0, end + 4).toString('latin1');

    if (!/^HTTP\/1\.[01] 101\b/m.test(handshake)) { client.write(responseBuffer); client.end(); upstream.destroy(); return; }

    client.write(responseBuffer);
    upstream.removeListener('data', onUpstreamData);

    if (target.hostname.startsWith('party.')) {
      const pageHost = target.hostname.replace(/^party\./, '');
      const needle = Buffer.from([0xa2, 0x69, 0x70, 0xd9, 0x20]);
      let tail = Buffer.alloc(0);
      upstream.on('data', (chunk) => {
        const combined = Buffer.concat([tail, chunk]);
        let idx = 0;
        while ((idx = combined.indexOf(needle, idx)) !== -1) {
          const hex = combined.slice(idx + needle.length, idx + needle.length + 32).toString('ascii');
          if (/^[0-9a-f]{32}$/.test(hex)) {
            lastMatchIpByPageHost.set(hex, hex);
            console.log(`[proxy] captured match ip ${hex.slice(0, 8)}...`);
          }
          idx += needle.length;
        }
        tail = combined.slice(-80);
      });
    }
    upstream.pipe(client);
  };
  upstream.on('data', onUpstreamData);
  upstream.on('error', () => client.destroy());
  client.on('error', () => upstream.destroy());
}

server.on('upgrade', async (req, client, head) => {
  let local; try { local = new URL(req.url, `http://${HOST}:${PORT}`); } catch { return client.destroy(); }
  const auth = authenticateProxy(req, local);
  if (!auth) { client.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return client.destroy(); }

  if (auth.wsCount >= MAX_WS_PER_SESSION) {
    client.write('HTTP/1.1 503 Service Unavailable\r\n\r\n'); return client.destroy();
  }

  let target;
  try {
    const match = local.pathname.match(/^\/_ws\/([A-Za-z0-9_-]+)(\/.*)?$/);
    if (!match) throw new Error('Invalid WS path');
    target = decodeTarget(match[1]);
    target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
    if (match[2]) target.pathname = match[2];
    await validatePublicTarget(target);
  } catch (e) {
    client.write('HTTP/1.1 400 Bad Request\r\n\r\n'); return client.destroy();
  }

  auth.wsCount++;
  client.once('close', () => auth.wsCount--);
  
  await relayUpgrade(req, client, head, target, null, auth.token);
});

server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Proxy listening on :${PORT}`);
});