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
const TOKEN_PATH = path.join(__dirname, '.proxy-token');

let PROXY_TOKEN = null;

function encodeTarget(value) {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function decodeTarget(value) {
  if (!/^[A-Za-z0-9_-]{1,12000}$/.test(value)) throw new Error('Invalid proxy address.');
  const target = new URL(Buffer.from(value, 'base64url').toString('utf8'));
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS are supported.');
  return target;
}

function loadOrCreateToken() {
  if (process.env.PROXY_TOKEN) return process.env.PROXY_TOKEN;
  try {
    const existing = fs.readFileSync(TOKEN_PATH, 'utf8').trim();
    if (existing) return existing;
  } catch { /* ignore */ }
  const token = crypto.randomBytes(32).toString('base64url');
  try { fs.writeFileSync(TOKEN_PATH, `${token}\n`, { mode: 0o600 }); } catch { /* ignore */ }
  console.log(`Launcher token: ${token}`);
  return token;
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
  const answers = await lookup(hostname, { all: true, verbatim: true });
  if (!answers.length || answers.some((a) => isPrivateAddress(a.address))) throw new Error('Did not resolve to public.');
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
    const encode = value => btoa(unescape(encodeURIComponent(value))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
    
    const proxify = value => {
      if (typeof value !== 'string') value = String(value);
      if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(value)) return value;
      try {
        let current = new URL(value, TARGET_BASE);
        if (!['http:','https:'].includes(current.protocol)) return value;
        if (!current.hostname.includes('.')) return value;
        
        if (current.pathname.startsWith('/p/')) return current.pathname + current.search;
        if (current.hostname === window.location.hostname) return current.pathname + current.search;

        return '/p/' + encode(current.origin) + current.pathname + current.search;
      } catch { return value; }
    };
    
    // 1. Intercept Fetch/XHR to force cookies for final.pkg
    const originalFetch = window.fetch.bind(window);
    window.fetch = async function(input, init){
      const request = input instanceof Request ? input : new Request(input, init);
      const proxified = proxify(request.url);
      const options = {
        method: request.method, headers: request.headers,
        mode: request.mode === 'navigate' ? 'cors' : request.mode,
        credentials: 'include', // FORCE COOKIES
        cache: request.cache, redirect: request.redirect, integrity: request.integrity, signal: request.signal,
      };
      if (request.body && !['GET', 'HEAD'].includes(request.method)) {
        options.body = await request.clone().arrayBuffer();
      }
      return originalFetch(proxified, options);
    };
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest){ return originalOpen.call(this, method, proxify(String(url)), ...rest); };

    // 2. Intercept WebSockets to fix ERR_NAME_NOT_RESOLVED
    const NativeWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      let newUrl = url;
      try {
        if (url.startsWith('ws://') || url.startsWith('wss://')) {
          const urlObj = new URL(url);
          if (urlObj.hostname !== window.location.hostname) {
            const targetOrigin = urlObj.origin.replace(/^wss?:/i, 'https://');
            newUrl = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + 
                     window.location.host + '/_ws/' + encode(targetOrigin + urlObj.pathname + urlObj.search);
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

    // 3. Intercept Service Workers (Catches hidden asset loads)
    if (navigator.serviceWorker) {
      const originalRegister = navigator.serviceWorker.register;
      navigator.serviceWorker.register = function(scriptURL, options) {
        console.log("[Proxy] Intercepted Service Worker:", scriptURL);
        return originalRegister.call(this, proxify(scriptURL), options);
      };
    }

    // 4. Patch DOM URLs
    const patchUrlProperty = (prototype, property) => {
      const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
      if (!descriptor || !descriptor.get || !descriptor.set || !descriptor.configurable) return;
      Object.defineProperty(prototype, property, {
        configurable: descriptor.configurable, enumerable: descriptor.enumerable,
        get(){ return descriptor.get.call(this); },
        set(value){ descriptor.set.call(this, typeof value === 'string' ? proxify(value) : value); }
      });
    };
    patchUrlProperty(HTMLIFrameElement.prototype, 'src');
    patchUrlProperty(HTMLScriptElement.prototype, 'src');
    patchUrlProperty(HTMLImageElement.prototype, 'src');
    patchUrlProperty(HTMLLinkElement.prototype, 'href');
    patchUrlProperty(HTMLMediaElement.prototype, 'src');
  })();</script>`;
  
  if (/<head\b[^>]*>/i.test(rewritten)) rewritten = rewritten.replace(/<head\b[^>]*>/i, (head) => `${head}${runtime}`);
  else rewritten = runtime + rewritten;
  return rewritten;
}

async function readRequestBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > MAX_REQUEST_BYTES) throw new Error('Too large'); chunks.push(chunk); }
  return size ? Buffer.concat(chunks) : undefined;
}

async function proxyRequest(req, res, target) {
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
  outHeaders.set('access-control-allow-origin', '*');
  outHeaders.set('access-control-allow-credentials', 'true');

  const location = upstream.headers.get('location');
  if (location) {
    try { outHeaders.set('location', proxyPath(new URL(location, target))); } catch {}
  }

  const contentType = upstream.headers.get('content-type') || '';
  if (/text\/html/i.test(contentType)) {
    const html = rewriteHtml(await upstream.text(), target);
    outHeaders.set('content-type', 'text/html; charset=utf-8');
    res.writeHead(upstream.status, Object.fromEntries(outHeaders));
    return res.end(html);
  }
  if (/text\/css/i.test(contentType)) {
    const css = rewriteCss(await upstream.text(), target);
    outHeaders.set('content-type', 'text/css; charset=utf-8');
    res.writeHead(upstream.status, Object.fromEntries(outHeaders));
    return res.end(css);
  }

  res.writeHead(upstream.status, Object.fromEntries(outHeaders));
  if (!upstream.body || req.method === 'HEAD') return res.end();
  Readable.fromWeb(upstream.body).pipe(res);
}

const server = http.createServer({ timeout: 0 }, async (req, res) => {
  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); } catch { return res.writeHead(400).end(); }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' });
    return res.end();
  }

  // Handle Proxy paths
  if (local.pathname.startsWith('/p/')) {
    if (local.searchParams.has('__k')) {
      const session = local.searchParams.get('__k');
      const cleanUrl = new URL(req.url, `http://${HOST}:${PORT}`);
      cleanUrl.searchParams.delete('__k');
      res.writeHead(302, {
        'Location': cleanUrl.pathname + cleanUrl.search,
        'Set-Cookie': `__pv_proxy=${session}; HttpOnly; SameSite=None; Secure; Path=/; Max-Age=86400`,
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

    return proxyRequest(req, res, target);
  }

  // Handle Launcher UI
  if (req.method === 'GET' && local.pathname === '/') {
    let page = fs.readFileSync(PAGE_PATH, 'utf8').replaceAll('__PROXY_PORT__', String(PORT));
    page = page.replace('__PV_SESSION_JSON__', JSON.stringify(PROXY_TOKEN));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(page);
  }

  return res.writeHead(404).end('Not found');
});

async function relayUpgrade(req, client, head, target) {
  const secure = target.protocol === 'wss:';
  const port = Number(target.port) || (secure ? 443 : 80);
  const upstream = secure ? tls.connect({ host: target.hostname, port, servername: target.hostname }) : net.connect({ host: target.hostname, port });

  upstream.once(secure ? 'secureConnect' : 'connect', () => {
    const lines = [`${req.method} ${target.pathname}${target.search} HTTP/${req.httpVersion}`];
    for (const [name, value] of Object.entries(req.headers)) {
      if (name.toLowerCase() === 'host') lines.push(`Host: ${target.host}`);
      else if (name.toLowerCase() !== 'cookie' && value) lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
    }
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head?.length) upstream.write(head);
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

server.on('upgrade', async (req, client, head) => {
  let local; try { local = new URL(req.url, `http://${HOST}:${PORT}`); } catch { return client.destroy(); }

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
  await relayUpgrade(req, client, head, target);
});

PROXY_TOKEN = loadOrCreateToken();
server.listen(PORT, BIND_ADDRESS, () => {
  console.log(`Proxy listening on :${PORT}`);
});