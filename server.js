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
const BIND_ADDRESS = process.env.BIND_ADDRESS || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const PAGE_PATH = path.join(__dirname, 'index.html');
const TOKEN_PATH = path.join(__dirname, '.proxy-token');
const STREAM_DIAGNOSTICS_PATH = path.join(__dirname, 'stream-diagnostics.log');
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
const PROXY_LOG_MODE = (process.env.PROXY_LOG_MODE || 'all').toLowerCase();
const STREAM_WIDTH = 1280;
const STREAM_HEIGHT = 720;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const TRUST_FORWARDED = process.env.TRUST_FORWARDED === 'true';
const FRAME_ANCESTORS = process.env.PV_ALLOW_EMBED === 'true' ? '*' : "'self'";
const DEBUG = process.env.DEBUG === 'true';

const MAX_SESSIONS = 6;
const MAX_STREAMS_PER_SESSION = 1;
const MAX_WS_PER_SESSION = 20;
const IDLE_STREAM_MS = 10 * 60 * 1000;
const MAX_BUCKET_ENTRIES = 10000;
const DNS_CACHE_TTL_MS = 60 * 1000;
const DNS_CACHE_MAX = 1000;

const proxyHostTargets = new Map();
const lastMatchIpByPageHost = new Map();
const streamSessions = new Map();
const sessions = new Map();
const buckets = new Map();
const bans = new Map();
const byteWindows = new Map();
const authFailures = new Map();
const authBans = new Map();
const dnsCache = new Map();
let PROXY_TOKEN = null;
let tlsOptions = null;
let nextCdpId = 1;

const PROXY_DIAGNOSTICS_AGENT = `<script>(function(){
  if (window.parent === window) return;
  if (window.__inpageDiagnosticsInstalled) return;
  window.__inpageDiagnosticsInstalled = true;
  var clean = function (value) {
    var text = String(value == null ? '' : value);
    var marker = text.indexOf('/p/');
    if (marker >= 0) {
      var rest = text.slice(marker + 3);
      var slash = rest.indexOf('/');
      text = slash >= 0 ? rest.slice(slash) : '/';
    } else {
      var scheme = text.indexOf('://');
      if (scheme >= 0) {
        var afterScheme = text.indexOf('/', scheme + 3);
        text = afterScheme >= 0 ? text.slice(afterScheme) : '/';
      }
    }
    text = text.replace(/([?&])__k=[^&]*/g, '$1').replace(/[?&]$/, '');
    return text.slice(0, 600);
  };
  var send = function (level, message, detail) {
    try {
      window.parent.postMessage({
        type: 'inpage-diagnostic',
        level: String(level || 'info').slice(0, 40),
        message: String(message == null ? '' : message).slice(0, 500),
        detail: detail ? String(detail).slice(0, 1500) : ''
      }, '*');
    } catch (error) { /* parent is gone */ }
  };
  window.addEventListener('error', function (event) {
    var target = event.target;
    if (target && target !== window && target.tagName) {
      send('resource', target.tagName.toLowerCase() + ' failed to load', clean(target.src || target.href || ''));
    } else {
      send('error', event.message || 'Script error', clean((event.filename || '') + (event.lineno ? ':' + event.lineno : '')));
    }
  }, true);
  window.addEventListener('unhandledrejection', function (event) {
    var reason = event.reason;
    send('rejection', clean((reason && (reason.stack || reason.message)) || reason || 'Unhandled promise rejection'));
  });
  var originalError = console.error;
  console.error = function () {
    var text = Array.prototype.map.call(arguments, function (value) {
      try { return typeof value === 'string' ? value : JSON.stringify(value); } catch (error) { return String(value); }
    }).join(' ');
    send('console', clean(text));
    return originalError.apply(console, arguments);
  };
  var originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    try {
      this.__inpageMethod = String(method || '');
      this.__inpageUrl = clean(url);
    } catch (error) { /* ignore */ }
    return originalOpen.apply(this, arguments);
  };
  var originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    try {
      if (this.__inpageMethod === 'POST' && this.__inpageUrl && this.__inpageUrl.indexOf('/script') >= 0) {
        if (typeof body === 'string') send('report', 'game error report', body);
        else if (body instanceof ArrayBuffer) send('report', 'game error report', new TextDecoder().decode(body));
        else if (body && typeof body.text === 'function') body.text().then(function (text) { send('report', 'game error report', text); });
      }
    } catch (error) { /* ignore */ }
    return originalSend.apply(this, arguments);
  };
})();</script>`;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function streamDiagnostic(sessionId, message) {
  const prefix = sessionId ? `${String(sessionId).slice(0, 8)} ` : '';
  const line = `[${new Date().toISOString()}] ${prefix}${message}`;
  console.log(line);
  try { fs.appendFileSync(STREAM_DIAGNOSTICS_PATH, `${line}\n`, 'utf8'); } catch { /* best effort */ }
}

function logProxy(method, target, status, detail = '') {
  const safeTarget = `${proxyHostname(target.hostname)}`;
  const suffix = detail ? ` ${detail}` : '';
  console.log(`[proxy ${new Date().toISOString()}] ${method} ${safeTarget} -> ${status}${suffix}`);
}

function logProxyRouteFailure(req, status, detail) {
  console.log(`[proxy ${new Date().toISOString()}] ${req.method} ${req.headers.host || 'proxy'} -> ${status} ${detail}`);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function getClientIp(req) {
  if (TRUST_FORWARDED) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const first = String(Array.isArray(xff) ? xff[0] : xff).split(',')[0].trim();
      if (first) return first;
    }
  }
  return req.socket.remoteAddress || '';
}

function getSocketProto(req) {
  if (TRUST_FORWARDED) {
    const proto = req.headers['x-forwarded-proto'];
    if (proto) return String(Array.isArray(proto) ? proto[0] : proto).split(',')[0].trim() || (req.socket.encrypted ? 'https' : 'http');
  }
  return req.socket.encrypted ? 'https' : 'http';
}

function stripProxyCookies(cookieHeader) {
  if (!cookieHeader) return '';
  return String(cookieHeader)
    .split(';')
    .map((c) => c.trim())
    .filter((c) => c && !/^__pv_auth=/i.test(c) && !/^__pv_proxy=/i.test(c))
    .join('; ');
}

function stripKParam(search) {
  if (!search || search === '?') return '';
  const params = new URLSearchParams(search);
  params.delete('__k');
  const s = params.toString();
  return s ? `?${s}` : '';
}

function responseChunkSize(chunk, encoding) {
  if (typeof chunk === 'string') return Buffer.byteLength(chunk, encoding);
  return chunk && typeof chunk.byteLength === 'number' ? chunk.byteLength : 0;
}

function isLocalhostHost(req) {
  const host = String(req.headers.host || '').split(':')[0];
  return host.endsWith('localhost') || host === '127.0.0.1';
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

function loadOrCreateToken() {
  if (process.env.PROXY_TOKEN) {
    if (process.env.PROXY_TOKEN.length < 16) {
      console.error('PROXY_TOKEN must be at least 16 characters.');
      process.exit(1);
    }
    return process.env.PROXY_TOKEN;
  }
  try {
    const existing = fs.readFileSync(TOKEN_PATH, 'utf8').trim();
    if (existing) return existing;
  } catch { /* file does not exist yet */ }
  const token = crypto.randomBytes(32).toString('base64url');
  try {
    fs.writeFileSync(TOKEN_PATH, `${token}\n`, { mode: 0o600 });
  } catch (error) {
    console.error(`Could not write ${TOKEN_PATH}: ${error.message}`);
    process.exit(1);
  }
  console.log(`Launcher token: ${token}`);
  return token;
}

function createSession(req) {
  if (buckets.size >= MAX_BUCKET_ENTRIES) return null;
  const token = crypto.randomBytes(32).toString('base64url');
  const session = {
    token,
    ip: getClientIp(req),
    ua: String(req.headers['user-agent'] || '').slice(0, 400),
    created: Date.now(),
    expires: Date.now() + SESSION_TTL_MS,
    wsCount: 0,
  };
  sessions.set(token, session);
  return session;
}

function getSessionFromCookie(cookie, name) {
  if (!cookie) return null;
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session) return null;
  if (session.expires < Date.now()) {
    sessions.delete(match[1]);
    return null;
  }
  return session;
}

function authenticateProxy(req, parsedPath) {
  const fromCookie = getSessionFromCookie(req.headers.cookie, '__pv_proxy');
  if (fromCookie) return { session: fromCookie, source: 'cookie' };
  if (parsedPath && parsedPath.searchParams.has('__k')) {
    const k = parsedPath.searchParams.get('__k') || '';
    const session = sessions.get(k);
    if (session && session.expires > Date.now()) return { session, source: 'query' };
  }
  return null;
}

function pruneSessions() {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expires < now) sessions.delete(token);
  }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

function isBanned(key) {
  const until = bans.get(key);
  if (!until) return null;
  if (until < Date.now()) {
    bans.delete(key);
    console.log(`[rate] unban ${key}`);
    return null;
  }
  return until;
}

function takeToken(key, ratePerSec, burst, banMs) {
  const now = Date.now();
  const activeBan = isBanned(key);
  if (activeBan) return { ok: false, banned: true, retryAfter: Math.ceil((activeBan - now) / 1000) };
  let b = buckets.get(key);
  if (!b) {
    b = { tokens: burst, last: now, strikes: [] };
    buckets.set(key, b);
  }
  const elapsed = (now - b.last) / 1000;
  b.tokens = Math.min(burst, b.tokens + elapsed * ratePerSec);
  b.last = now;
  if (b.tokens >= 1) {
    b.tokens -= 1;
    return { ok: true };
  }
  if (b.strikes.length === 0 || now - b.strikes[b.strikes.length - 1] >= 1000) {
    b.strikes.push(now);
  }
  b.strikes = b.strikes.filter((t) => now - t < 60000);
  if (b.strikes.length >= 3) {
    bans.set(key, now + banMs);
    console.log(`[rate] ban ${key} ${banMs}ms`);
    return { ok: false, banned: true, retryAfter: Math.ceil(banMs / 1000) };
  }
  return { ok: false, retryAfter: 1 };
}

function checkBytes(sessionId, delta) {
  const now = Date.now();
  let w = byteWindows.get(sessionId);
  if (!w || now - w.windowStart >= 60000) {
    w = { windowStart: now, bytes: 0, strikes: w ? w.strikes.filter((t) => now - t < 60000) : [] };
    byteWindows.set(sessionId, w);
  }
  w.bytes += delta;
  if (w.bytes > 200 * 1024 * 1024) {
    if (w.strikes.length === 0 || now - w.strikes[w.strikes.length - 1] >= 1000) {
      w.strikes.push(now);
      console.log(`[rate] byte strike sid=${sessionId.slice(0, 8)} window=${Math.round(w.bytes / 1024 / 1024)}MB`);
    }
    if (w.strikes.length >= 3) {
      const banKey = `proxy:${sessionId}`;
      if (!bans.has(banKey)) {
        bans.set(banKey, now + 600000);
        console.log(`[rate] ban ${banKey} 600000ms`);
      }
    }
    return false;
  }
  return true;
}

function recordAuthFailure(ip) {
  const now = Date.now();
  const banUntil = authBans.get(ip);
  if (banUntil && banUntil > now) return true;
  let failures = authFailures.get(ip) || [];
  failures = failures.filter((t) => now - t < 60000);
  failures.push(now);
  authFailures.set(ip, failures);
  if (failures.length >= 5) {
    authBans.set(ip, now + 600000);
    authFailures.delete(ip);
    console.log(`[rate] ban auth:${ip} 600000ms`);
    return true;
  }
  return false;
}

function isAuthBanned(ip) {
  const now = Date.now();
  const banUntil = authBans.get(ip);
  if (!banUntil) return false;
  if (banUntil < now) {
    authBans.delete(ip);
    console.log(`[rate] unban auth:${ip}`);
    return false;
  }
  return true;
}

function cleanupRateLimits() {
  const now = Date.now();
  for (const [key, ban] of bans) {
    if (ban < now) { bans.delete(key); console.log(`[rate] unban ${key}`); }
  }
  for (const [ip, ban] of authBans) {
    if (ban < now) { authBans.delete(ip); console.log(`[rate] unban auth:${ip}`); }
  }
  for (const [key, b] of buckets) {
    if (b.strikes.length === 0 && now - b.last > 5 * 60 * 1000) buckets.delete(key);
  }
  for (const [key, w] of byteWindows) {
    if (now - w.windowStart >= 60000 && w.strikes.length === 0) byteWindows.delete(key);
  }
  for (const [ip, failures] of authFailures) {
    const fresh = failures.filter((t) => now - t < 60000);
    if (fresh.length === 0) authFailures.delete(ip);
    else authFailures.set(ip, fresh);
  }
  for (const [sessionId, session] of streamSessions) {
    if (session.child && session.child.exitCode !== null) {
      streamSessions.delete(sessionId);
      continue;
    }
    const idle = session.clients.size === 0 && (now - session.lastFrameAt) > IDLE_STREAM_MS;
    if (idle) {
      console.log(`[stream] idle eviction sid=${sessionId.slice(0, 8)}`);
      stopStream(sessionId).catch(() => {});
    }
  }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  const scheme = res.socket?.encrypted ? 'https' : 'http';
  const headers = {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': `default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors ${FRAME_ANCESTORS}`,
  };
  if (tlsOptions) headers['Strict-Transport-Security'] = 'max-age=31536000';
  res.writeHead(status, headers);
  res.end(body);
}

function sendUnauthorized(res, message = 'Authentication required.') {
  res.writeHead(401, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'WWW-Authenticate': 'Bearer realm="pv"',
    'X-Request-Id': crypto.randomUUID(),
  });
  res.end(message);
}

function rateLimited(res, retryAfter = 1) {
  res.writeHead(429, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Retry-After': String(retryAfter),
    'X-Request-Id': crypto.randomUUID(),
  });
  res.end('Rate limit exceeded.');
}

function forbidden(res, message = 'Forbidden.') {
  res.writeHead(403, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Request-Id': crypto.randomUUID(),
  });
  res.end(message);
}

function serviceUnavailable(res, message = 'Service unavailable.') {
  res.writeHead(503, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Retry-After': '60',
    'X-Request-Id': crypto.randomUUID(),
  });
  res.end(message);
}

// ---------------------------------------------------------------------------
// Chrome / streaming
// ---------------------------------------------------------------------------

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
  path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
  path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
];

function findChrome() {
  return CHROME_CANDIDATES.find((candidate) => candidate && fs.existsSync(candidate));
}

async function waitForDevToolsPort(session) {
  const portFile = path.join(session.profile, 'DevToolsActivePort');
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (session.child.exitCode !== null || session.child.signalCode !== null) throw new Error('The hidden Chrome process exited during startup.');
    try {
      const [port] = fs.readFileSync(portFile, 'utf8').split(/\r?\n/);
      if (/^\d+$/.test(port)) return Number(port);
    } catch { /* Chrome has not written its remote-debugging port yet. */ }
    await wait(100);
  }
  throw new Error('Timed out waiting for hidden Chrome to start.');
}

function cdpCommand(session, method, params = {}) {
  if (!session.socket || session.socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('The hidden browser connection is closed.'));
  const id = nextCdpId++;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      session.pending.delete(id);
      reject(new Error(`Timed out waiting for browser command ${method}.`));
    }, 10000);
    session.pending.set(id, { resolve, reject, timeout, method });
    session.socket.send(JSON.stringify({ id, method, params }));
  });
}

function cdpNotify(session, method, params = {}) {
  if (!session.socket || session.socket.readyState !== WebSocket.OPEN) return;
  try { session.socket.send(JSON.stringify({ id: nextCdpId++, method, params })); } catch { /* socket closed */ }
}

function frameChunk(jpeg) {
  const header = Buffer.from(`--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ${jpeg.length}\r\n\r\n`);
  return Buffer.concat([header, jpeg, Buffer.from('\r\n')]);
}

function emitStreamFrame(session, jpeg) {
  const frame = frameChunk(jpeg);
  const prime = session.frames === 0;
  for (const client of session.clients) {
    if (client.destroyed) continue;
    if (!prime && client.writableLength > frame.length) {
      session.skippedFrames += 1;
      continue;
    }
    client.write(frame);
    if (prime) client.write(frame);
  }
  session.frames += 1;
  session.lastFrameAt = Date.now();
  if (session.skippedFrames && Date.now() - (session.lastSkipLogAt || 0) > 1000) {
    streamDiagnostic(session.sessionId, `viewer behind: skipped ${session.skippedFrames} frame(s)`);
    session.skippedFrames = 0;
    session.lastSkipLogAt = Date.now();
  }
}

async function startStream(sessionId, target) {
  await validatePublicTarget(target);
  await stopStream(sessionId);

  const chrome = findChrome();
  if (!chrome) throw new Error('Google Chrome was not found.');

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'website-viewer-'));
  const session = {
    sessionId,
    profile,
    child: null,
    socket: null,
    pending: new Map(),
    frames: 0,
    lastFrameAt: Date.now(),
    latestJpeg: null,
    stderr: '',
    width: STREAM_WIDTH,
    height: STREAM_HEIGHT,
    reportedState: null,
    reportedFrameSize: null,
    resizeChain: Promise.resolve(),
    lastMoveLogAt: 0,
    lastInputLogAt: 0,
    skippedFrames: 0,
    lastSkipLogAt: 0,
    observedPointerLock: false,
    observedFullscreen: false,
    clients: new Set(),
  };
  streamSessions.set(sessionId, session);

  session.child = spawn(chrome, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1',
    '--remote-allow-origins=*',
    `--user-data-dir=${profile}`,
    '--disable-extensions',
    '--disable-background-networking',
    '--no-first-run',
    '--no-default-browser-check',
    '--autoplay-policy=no-user-gesture-required',
    '--enable-gpu',
    '--use-angle=d3d11',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    `--window-size=${STREAM_WIDTH},${STREAM_HEIGHT}`,
    '--force-device-scale-factor=1',
    'about:blank',
  ], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
  session.child.stderr.setEncoding('utf8');
  session.child.stderr.on('data', (chunk) => { session.stderr = (session.stderr + chunk).slice(-4096); });
  session.child.once('exit', (code, signal) => {
    for (const pending of session.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('The hidden Chrome process exited.'));
    }
    session.pending.clear();
    if (streamSessions.get(sessionId) === session) streamSessions.delete(sessionId);
    if (code !== 0 && signal !== 'SIGTERM') {
      const diagnostics = session.stderr.split(/\r?\n/).filter((line) => line && !line.includes('DevTools listening on')).slice(-8).join(' | ');
      console.error(`[stream] Chrome exited code=${code} signal=${signal || 'none'}${diagnostics ? `: ${diagnostics}` : ''}`);
    }
    fs.rm(profile, { recursive: true, force: true }, () => {});
  });

  try {
    const port = await waitForDevToolsPort(session);
    const listResponse = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(5000) });
    const targets = await listResponse.json();
    let page = targets.find((item) => item.type === 'page');
    if (!page) {
      const newResponse = await fetch(`http://127.0.0.1:${port}/json/new?about%3Ablank`, { method: 'PUT', signal: AbortSignal.timeout(5000) });
      if (!newResponse.ok) throw new Error('Could not create a hidden browser page.');
      page = await newResponse.json();
    }

    session.socket = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timed out connecting to hidden Chrome.')), 10000);
      session.socket.addEventListener('open', () => { clearTimeout(timeout); resolve(); }, { once: true });
      session.socket.addEventListener('error', () => { clearTimeout(timeout); reject(new Error('Could not connect to hidden Chrome.')); }, { once: true });
    });
    session.socket.addEventListener('message', async (event) => {
      let message;
      try {
        const data = typeof event.data === 'string' ? event.data : await event.data.text();
        message = JSON.parse(data);
      } catch { return; }
      if (message.id) {
        const pending = session.pending.get(message.id);
        if (!pending) return;
        clearTimeout(pending.timeout);
        session.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message || `Browser command ${pending.method} failed.`));
        else pending.resolve(message.result || {});
        return;
      }
      if (message.method === 'Runtime.consoleAPICalled') {
        const args = message.params?.args || [];
        if (args[0]?.value === '[stream-diag]') {
          const details = args.slice(1).map((arg) => String(arg.value ?? '')).join(' ');
          if (details.startsWith('pointerlockchange ')) {
            session.observedPointerLock = /pointerLock=true\b/.test(details);
            session.reportedState = null;
          }
          if (details.startsWith('fullscreenchange ')) {
            session.observedFullscreen = /\bfullscreen=true\b/.test(details);
            session.reportedState = null;
          }
          streamDiagnostic(sessionId, `page ${details}`);
        }
      }
      if (message.method === 'Page.screencastFrame') {
        const { data, sessionId: frameSessionId, metadata } = message.params;
        const frameSize = `${metadata?.deviceWidth || '?'}x${metadata?.deviceHeight || '?'} scale=${metadata?.pageScaleFactor ?? '?'}`;
        if (session.reportedFrameSize !== frameSize) {
          session.reportedFrameSize = frameSize;
          streamDiagnostic(sessionId, `captured frame viewport=${frameSize}`);
        }
        session.latestJpeg = Buffer.from(data, 'base64');
        emitStreamFrame(session, session.latestJpeg);
        cdpCommand(session, 'Page.screencastFrameAck', { sessionId: frameSessionId }).catch(() => {});
      }
    });
    session.socket.addEventListener('close', () => {
      if (streamSessions.get(sessionId) === session) console.log('[stream] hidden browser connection closed.');
    });

    await cdpCommand(session, 'Page.enable');
    await cdpCommand(session, 'Runtime.enable');
    try { await cdpCommand(session, 'Page.bringToFront'); } catch { /* optional */ }
    await cdpCommand(session, 'Emulation.setFocusEmulationEnabled', { enabled: true });
    await cdpCommand(session, 'Page.addScriptToEvaluateOnNewDocument', {
      source: `(() => {
        let virtualPointerLockElement = null;
        let virtualFullscreenElement = null;
        const pointerLockDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'pointerLockElement');
        const nativePointerLockElement = () => {
          try { return pointerLockDescriptor?.get?.call(document) || null; } catch { return null; }
        };
        const report = (reason) => console.debug('[stream-diag]', reason, innerWidth + 'x' + innerHeight,
          'fullscreen=' + Boolean(document.fullscreenElement), 'pointerLock=' + Boolean(document.pointerLockElement));
        try { Object.defineProperty(document, 'pointerLockElement', { configurable: true, get: () => virtualPointerLockElement || nativePointerLockElement() }); } catch {}
        try { Object.defineProperty(window, '__streamLockMode', { configurable: true, get: () => (virtualPointerLockElement ? 'virtual' : (nativePointerLockElement() ? 'native' : null)) }); } catch {}
        try { Object.defineProperty(document, 'fullscreenElement', { configurable: true, get: () => virtualFullscreenElement }); } catch {}
        try { Object.defineProperty(document, 'webkitFullscreenElement', { configurable: true, get: () => virtualFullscreenElement }); } catch {}
        try { Object.defineProperty(document, 'webkitCurrentFullscreenElement', { configurable: true, get: () => virtualFullscreenElement }); } catch {}
        try { Object.defineProperty(document, 'fullscreenEnabled', { configurable: true, get: () => true }); } catch {}
        try { Object.defineProperty(document, 'webkitFullscreenEnabled', { configurable: true, get: () => true }); } catch {}
        addEventListener('resize', () => report('window-resize'));
        document.addEventListener('fullscreenchange', () => report('fullscreenchange'));
        document.addEventListener('pointerlockchange', () => report('pointerlockchange'));
        const pointerLockChanged = () => {
          document.dispatchEvent(new Event('pointerlockchange', { bubbles: true }));
          report('pointerlockchange');
        };
        const nativeRequestPointerLock = Element.prototype.requestPointerLock;
        const nativeExitPointerLock = Document.prototype.exitPointerLock;
        for (const name of ['requestPointerLock', 'webkitRequestPointerLock', 'mozRequestPointerLock']) {
          try { Object.defineProperty(Element.prototype, name, { configurable: true, value: function() {
            report('pointerlock-api-' + name);
            const element = this;
            if (!element.isConnected) return Promise.reject(new DOMException('Pointer lock target is detached.', 'WrongDocumentError'));
            const fallback = () => {
              if (virtualPointerLockElement !== element) {
                virtualPointerLockElement = element;
                pointerLockChanged();
              }
              return element;
            };
            if (typeof nativeRequestPointerLock !== 'function') return Promise.resolve(fallback());
            let request;
            try { request = nativeRequestPointerLock.call(element); } catch { request = null; }
            if (!request || typeof request.then !== 'function') return Promise.resolve(fallback());
            return request.then(
              () => (nativePointerLockElement() === element ? element : fallback()),
              () => fallback()
            );
          } }); } catch {}
        }
        for (const name of ['exitPointerLock', 'webkitExitPointerLock', 'mozExitPointerLock']) {
          try { Object.defineProperty(Document.prototype, name, { configurable: true, value: function() {
            if (virtualPointerLockElement) { virtualPointerLockElement = null; pointerLockChanged(); }
            if (typeof nativeExitPointerLock === 'function' && nativePointerLockElement()) {
              try { nativeExitPointerLock.call(document); } catch {}
            }
            return Promise.resolve();
          } }); } catch {}
        }
        const fullscreenChanged = () => {
          document.dispatchEvent(new Event('fullscreenchange', { bubbles: true }));
          document.dispatchEvent(new Event('webkitfullscreenchange', { bubbles: true }));
        };
        for (const name of ['requestFullscreen', 'webkitRequestFullscreen', 'webkitRequestFullScreen', 'mozRequestFullScreen', 'msRequestFullscreen']) {
          try { Object.defineProperty(Element.prototype, name, { configurable: true, value: function() {
            report('fullscreen-api-' + name);
            if (!this.isConnected) return Promise.reject(new DOMException('Full screen target is detached.', 'TypeError'));
            virtualFullscreenElement = this;
            fullscreenChanged();
            return Promise.resolve();
          } }); } catch {}
        }
        for (const name of ['exitFullscreen', 'webkitExitFullscreen', 'webkitCancelFullScreen', 'mozCancelFullScreen', 'msExitFullscreen']) {
          try { Object.defineProperty(Document.prototype, name, { configurable: true, value: function() {
            if (!virtualFullscreenElement) return Promise.resolve();
            virtualFullscreenElement = null;
            fullscreenChanged();
            return Promise.resolve();
          } }); } catch {}
        }
        if (window.top === window) {
          try {
            const probe = document.createElement('canvas');
            const gl = probe.getContext('webgl2') || probe.getContext('webgl');
            const info = gl && gl.getExtension('WEBGL_debug_renderer_info');
            console.debug('[stream-diag]', 'webgl', info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : (gl ? 'unknown renderer' : 'unavailable'));
            gl?.getExtension('WEBGL_lose_context')?.loseContext();
          } catch { /* diagnostics only */ }
        }
        report('document-start');
      })();`,
    });
    await cdpCommand(session, 'Emulation.setDeviceMetricsOverride', { width: STREAM_WIDTH, height: STREAM_HEIGHT, deviceScaleFactor: 1, mobile: false });
    await cdpCommand(session, 'Page.startScreencast', { format: 'jpeg', quality: 60, maxWidth: 3840, maxHeight: 2160, everyNthFrame: 1 });
    await cdpCommand(session, 'Page.navigate', { url: target.href });
    console.log('[stream] hidden browser started; target URL omitted from logs.');
  } catch (error) {
    await stopStream(sessionId);
    throw error;
  }
}

async function stopStream(sessionId) {
  const session = streamSessions.get(sessionId);
  if (!session) return;
  streamSessions.delete(sessionId);
  for (const client of session.clients) client.end();
  session.clients.clear();
  try { session.socket?.close(); } catch { /* already closed */ }
  for (const key of [...lastMatchIpByPageHost.keys()]) {
    if (key.startsWith(`${sessionId}:`)) lastMatchIpByPageHost.delete(key);
  }
  if (session.child && session.child.exitCode === null) {
    const exited = new Promise((resolve) => session.child.once('exit', resolve));
    session.child.kill();
    await Promise.race([exited, wait(3000)]);
  }
  fs.rm(session.profile, { recursive: true, force: true }, () => {});
}

async function stopAllStreams() {
  const ids = [...streamSessions.keys()];
  await Promise.all(ids.map((id) => stopStream(id)));
}

function dispatchStreamInput(session, input) {
  if (!session || !input || typeof input !== 'object') return;
  const command = (method, params) => { cdpNotify(session, method, params); };
  const now = Date.now();
  if (input.type === 'mouse' && ['mouseMoved', 'mousePressed', 'mouseReleased', 'mouseWheel'].includes(input.eventType)) {
    const params = { x: Number(input.x) || 0, y: Number(input.y) || 0, button: input.button || 'none', buttons: Number(input.buttons) || 0 };
    if (input.eventType === 'mouseMoved') {
      if (now - session.lastMoveLogAt > 1000) {
        session.lastMoveLogAt = now;
        streamDiagnostic(session.sessionId, `input mouseMoved buttons=${params.buttons} at=${Math.round(params.x)},${Math.round(params.y)}`);
      }
    } else if (now - session.lastInputLogAt > 300) {
      session.lastInputLogAt = now;
      streamDiagnostic(session.sessionId, `input ${input.eventType} button=${params.button} buttons=${params.buttons}`);
    }
    if (input.eventType === 'mouseWheel') {
      params.deltaX = Number(input.deltaX) || 0;
      params.deltaY = Number(input.deltaY) || 0;
    }
    command('Input.dispatchMouseEvent', { ...params, type: input.eventType, clickCount: Number(input.clickCount) || 1 });
  } else if (input.type === 'key' && ['keyDown', 'keyUp', 'rawKeyDown', 'char'].includes(input.eventType)) {
    if (now - session.lastInputLogAt > 1000) {
      session.lastInputLogAt = now;
      streamDiagnostic(session.sessionId, 'input key events');
    }
    command('Input.dispatchKeyEvent', {
      type: input.eventType,
      key: String(input.key || ''),
      code: String(input.code || ''),
      text: input.text ? String(input.text) : undefined,
      unmodifiedText: input.text ? String(input.text) : undefined,
      windowsVirtualKeyCode: Number(input.keyCode) || 0,
      nativeVirtualKeyCode: Number(input.keyCode) || 0,
      modifiers: Number(input.modifiers) || 0,
    });
  } else if (input.type === 'pointer' && input.eventType === 'exit') {
    command('Runtime.evaluate', { expression: 'document.exitPointerLock && document.exitPointerLock();' });
  } else if (input.type === 'text') {
    command('Input.insertText', { text: String(input.text || '').slice(0, 2048) });
  }
}

// ---------------------------------------------------------------------------
// Targets and proxy primitives
// ---------------------------------------------------------------------------

function encodeTarget(value) {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function decodeTarget(value) {
  if (!/^[A-Za-z0-9_-]{1,12000}$/.test(value)) throw new Error('Invalid proxy address.');
  const target = new URL(Buffer.from(value, 'base64url').toString('utf8'));
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS addresses are supported.');
  return target;
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (family === 6) {
    const normalized = address.toLowerCase();
    return normalized === '::' || normalized === '::1' || normalized.startsWith('fc') ||
      normalized.startsWith('fd') || /^fe[89ab]/.test(normalized) || normalized.startsWith('::ffff:');
  }
  return true;
}

async function validatePublicTarget(target) {
  const hostname = target.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    throw new Error('Local network addresses are not supported.');
  }
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new Error('Private network addresses are not supported.');
    return;
  }
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && cached.expires > now) {
    if (!cached.ok) throw new Error(cached.message);
    return;
  }
  try {
    const answers = await lookup(hostname, { all: true, verbatim: true });
    if (!answers.length || answers.some((answer) => isPrivateAddress(answer.address))) {
      const message = 'This host did not resolve to a public address.';
      if (dnsCache.size >= DNS_CACHE_MAX) {
        const oldest = [...dnsCache.entries()].sort((a, b) => a[1].expires - b[1].expires)[0];
        if (oldest) dnsCache.delete(oldest[0]);
      }
      dnsCache.set(hostname, { ok: false, message, expires: now + DNS_CACHE_TTL_MS });
      throw new Error(message);
    }
    if (dnsCache.size >= DNS_CACHE_MAX) {
      const oldest = [...dnsCache.entries()].sort((a, b) => a[1].expires - b[1].expires)[0];
      if (oldest) dnsCache.delete(oldest[0]);
    }
    dnsCache.set(hostname, { ok: true, expires: now + DNS_CACHE_TTL_MS });
  } catch (error) {
    if (error.message === 'This host did not resolve to a public address.') throw error;
    if (dnsCache.size >= DNS_CACHE_MAX) {
      const oldest = [...dnsCache.entries()].sort((a, b) => a[1].expires - b[1].expires)[0];
      if (oldest) dnsCache.delete(oldest[0]);
    }
    dnsCache.set(hostname, { ok: false, message: error.message, expires: now + 30000 });
    throw error;
  }
}

function proxyPath(target) {
  return `/p/${encodeTarget(target.origin)}${target.pathname}${target.search}`;
}

function proxyHostname(hostname) {
  let hash = 14695981039346656037n;
  for (const character of hostname.toLowerCase()) {
    hash ^= BigInt(character.charCodeAt(0));
    hash = BigInt.asUintN(64, hash * 1099511628211n);
  }
  return `p-${hash.toString(36)}`;
}

function resolveLink(value, base) {
  const raw = value.trim();
  if (!raw || raw.startsWith('#') || /^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(raw)) return value;
  try {
    const resolved = new URL(raw, base);
    if (!['http:', 'https:'].includes(resolved.protocol)) return value;
    return proxyPath(resolved);
  } catch {
    return value;
  }
}

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, value) => `url("${resolveLink(value, base)}")`)
    .replace(/@import\s+(?:url\()?\s*(['"])(.*?)\1\s*\)?/gi, (match, quote, value) => `@import url("${resolveLink(value, base)}")`);
}

function rewriteHtml(html, target) {
  const attrNames = ['href', 'src', 'action', 'formaction', 'poster', 'data', 'xlink:href'];
  const attrPattern = new RegExp(`(\\b(?:${attrNames.join('|')})\\s*=\\s*)(["'])(.*?)\\2`, 'gis');
  let rewritten = html.replace(attrPattern, (match, prefix, quote, value) => `${prefix}${quote}${resolveLink(value, target)}${quote}`);
  rewritten = rewritten.replace(/<meta\b[^>]*http-equiv\s*=\s*(["'])?content-security-policy\1?[^>]*>/gi, '');
  rewritten = rewritten.replace(/<meta\b[^>]*name\s*=\s*(["'])?referrer\1?[^>]*>/gi, '');
  rewritten = rewritten.replace(/srcset\s*=\s*(["'])(.*?)\1/gis, (match, quote, value) => {
    const entries = value.split(',').map((item) => {
      const parts = item.trim().split(/\s+/);
      if (!parts[0]) return item;
      parts[0] = resolveLink(parts[0], target);
      return parts.join(' ');
    });
    return `srcset=${quote}${entries.join(', ')}${quote}`;
  });
  rewritten = rewritten.replace(/<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi, (match, attrs, css) => `<style${attrs}>${rewriteCss(css, target)}</style>`);
  rewritten = rewritten.replace(/\sstyle=(['"])(.*?)\1/gi, (match, quote, css) => ` style=${quote}${rewriteCss(css, target)}${quote}`);

  const runtime = PROXY_DIAGNOSTICS_AGENT + `<script>(function(){
    const TARGET_TOKEN = ${JSON.stringify(encodeTarget(target.origin))};
    const TARGET_BASE = (function(){ const b=TARGET_TOKEN.replace(/-/g,'+').replace(/_/g,'/'); return new TextDecoder().decode(Uint8Array.from(atob(b+'='.repeat((4-b.length%4)%4)),c=>c.charCodeAt(0))); })();
    const REAL_HOSTNAME = window.location.hostname;
    const encode = value => btoa(unescape(encodeURIComponent(value))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');

    // 1. Spoof Location.prototype (window.location cannot be replaced)
    try {
      const FAKE_URL = new URL(TARGET_BASE);
      const locProps = ['origin', 'hostname', 'host', 'protocol', 'href', 'port'];
      locProps.forEach(prop => {
        const descriptor = Object.getOwnPropertyDescriptor(Location.prototype, prop);
        if (descriptor && descriptor.get) {
          Object.defineProperty(Location.prototype, prop, {
            configurable: true,
            get: function() {
              return FAKE_URL[prop];
            }
          });
        }
      });
    } catch (e) { console.warn('Location spoof failed', e); }

    // 2. Ironclad URL rewriter (prevents double-proxying)
    const proxify = value => {
      if (typeof value !== 'string') value = String(value);
      if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(value)) return value;
      try {
        let current = new URL(value, TARGET_BASE);
        if (!['http:','https:'].includes(current.protocol)) return value;
        if (!current.hostname.includes('.')) return value;

        // If it's a proxy path, extract the innermost path to prevent double-proxying
        if (current.pathname.includes('/p/')) {
           const idx = current.pathname.lastIndexOf('/p/');
           return current.pathname.substring(idx) + current.search;
        }

        // If it points to the real proxy host, leave it alone
        if (current.hostname === REAL_HOSTNAME) return current.pathname + current.search;

        return '/p/' + encode(current.origin) + current.pathname + current.search;
      } catch { return value; }
    };
    
    const originalFetch = window.fetch.bind(window);
    window.fetch = async function(input, init){
      const request = input instanceof Request ? input : new Request(input, init);
      const proxified = proxify(request.url);
      const options = {
        method: request.method,
        headers: request.headers,
        mode: request.mode === 'navigate' ? 'cors' : request.mode,
        credentials: request.credentials,
        cache: request.cache,
        redirect: request.redirect,
        integrity: request.integrity,
        signal: request.signal,
      };
      if (request.body && !['GET', 'HEAD'].includes(request.method)) {
        const body = await request.clone().arrayBuffer();
        if (body.byteLength > 32 * 1024 * 1024) throw new TypeError('This local proxy only buffers request bodies up to 32 MB.');
        options.body = body;
      }
      return originalFetch(proxified, options);
    };
    
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest){ return originalOpen.call(this, method, proxify(String(url)), ...rest); };
    const originalBeacon = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
    if (originalBeacon) navigator.sendBeacon = (url, data) => originalBeacon(proxify(String(url)), data);
    if (window.EventSource) {
      const NativeEventSource = window.EventSource;
      window.EventSource = function(url, options){ return new NativeEventSource(proxify(String(url)), options); };
      window.EventSource.prototype = NativeEventSource.prototype;
      window.EventSource.CONNECTING = NativeEventSource.CONNECTING;
      window.EventSource.OPEN = NativeEventSource.OPEN;
      window.EventSource.CLOSED = NativeEventSource.CLOSED;
    }
    const originalOpenWindow = window.open.bind(window);
    window.open = (url, ...rest) => originalOpenWindow(proxify(String(url)), ...rest);
    const originalSetAttribute = Element.prototype.setAttribute;
    const urlAttributes = new Set(['src','href','action','formaction','poster','data']);
    Element.prototype.setAttribute = function(name, value){
      if (urlAttributes.has(String(name).toLowerCase()) && typeof value === 'string') value = proxify(value);
      return originalSetAttribute.call(this, name, value);
    };
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
  const cookies = typeof response.headers.getSetCookie === 'function'
    ? response.headers.getSetCookie()
    : (response.headers.get('set-cookie') || '').split(/,(?=\s*[^;,]+=)/);
  const prefix = `/p/${encodeTarget(target.origin)}`;
  return cookies.map((cookie) => {
    let out = cookie.replace(/;\s*domain=[^;]*/i, '');
    out = out.replace(/;\s*path=([^;]*)/i, (m, p) => {
      const raw = (p.trim() || '/');
      const norm = raw.startsWith('/') ? raw : `/${raw}`;
      return `; Path=${prefix}${norm === '/' ? '' : norm}`;
    });
    if (/;\s*SameSite=(Lax|Strict)/i.test(out)) {
      out = out.replace(/;\s*SameSite=(Lax|Strict)/i, '; SameSite=None');
    } else if (!/;\s*SameSite=/i.test(out)) {
      out += '; SameSite=None';
    }
    if (!/;\s*Secure/i.test(out)) {
      out += '; Secure';
    }
    return out;
  });
}

async function readRequestBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) throw new Error('Request body is too large for this prototype.');
    chunks.push(chunk);
  }
  return size ? Buffer.concat(chunks) : undefined;
}

function targetFromRequest(req, parsedPath) {
  const match = parsedPath.pathname.match(/^\/p\/([A-Za-z0-9_-]+)(\/.*)?$/);
  if (match) {
    const target = decodeTarget(match[1]);
    const cleanSearch = stripKParam(parsedPath.search);
    if (match[2] && match[2] !== '/') {
      target.pathname = match[2];
      target.search = cleanSearch;
    } else if (cleanSearch) target.search = cleanSearch;
    else if (match[2] === '/') target.pathname = '/';
    return target;
  }
  return null;
}

function cleanSearchOnly(search) {
  return stripKParam(search);
}

function mapReferer(value) {
  if (!value) return undefined;
  try {
    const parsed = new URL(value);
    if (parsed.hostname.endsWith('.localhost') && Number(parsed.port) === PORT) {
      const match = parsed.pathname.match(/^\/p\/([A-Za-z0-9_-]+)(\/.*)?$/);
      if (match) return decodeTarget(match[1]).href;
    }
  } catch { /* ignored */ }
  return undefined;
}

async function proxyRequest(req, res, target, sessionId) {
  await validatePublicTarget(target);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (!value || ['host', 'connection', 'content-length', 'accept-encoding', 'origin', 'referer', 'cookie'].includes(lower)) continue;
    if (!TRUST_FORWARDED && ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'forwarded', 'x-real-ip'].includes(lower)) continue;
    if (Array.isArray(value)) headers.set(name, value.join(', '));
    else headers.set(name, value);
  }
  const cookie = stripProxyCookies(req.headers.cookie);
  if (cookie) headers.set('cookie', cookie);
  if (req.headers.origin) headers.set('origin', target.origin);
  const referer = mapReferer(req.headers.referer);
  if (referer) headers.set('referer', referer);
  if (!TRUST_FORWARDED) {
    headers.set('X-Forwarded-For', getClientIp(req));
    headers.set('X-Forwarded-Proto', getSocketProto(req));
  }

  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRequestBody(req);
  const controller = new AbortController();
  res.on('close', () => controller.abort());
  const upstream = await fetch(target, {
    method: req.method,
    headers,
    body,
    redirect: 'manual',
    signal: AbortSignal.any([AbortSignal.timeout(120000), controller.signal]),
  });
  res.proxyContentType = upstream.headers.get('content-type') || 'no-content-type';
  const upstreamContentType = upstream.headers.get('content-type') || '';
  const outHeaders = new Headers(upstream.headers);
  for (const name of [
    'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
    'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
    'permissions-policy',
    'access-control-allow-origin', 'access-control-allow-credentials', 'access-control-allow-headers',
    'access-control-allow-methods', 'access-control-expose-headers', 'access-control-max-age',
    'content-encoding', 'content-length', 'transfer-encoding', 'connection', 'alt-svc',
  ]) outHeaders.delete(name);
  if (/text\/html|application\/xhtml\+xml/i.test(upstreamContentType)) outHeaders.set('cache-control', 'no-store');
  outHeaders.set('referrer-policy', 'same-origin');
  const requestOrigin = req.headers.origin || `http://${req.headers.host}`;
  if (/^https?:\/\/[a-z0-9.:-]+$/i.test(requestOrigin)) outHeaders.set('access-control-allow-origin', requestOrigin);
  else outHeaders.set('access-control-allow-origin', `http://${req.headers.host}`);
  outHeaders.set('access-control-allow-credentials', 'true');
  outHeaders.set('access-control-allow-methods', 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS');
  const requestedHeaders = req.headers['access-control-request-headers'];
  outHeaders.set('access-control-allow-headers', requestedHeaders || 'Content-Type, Authorization, Signature, Signature-Agent');
  outHeaders.set('access-control-expose-headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Type');
  const cookies = responseCookies(upstream, target);
  outHeaders.delete('set-cookie');

  const location = upstream.headers.get('location');
  if (location) {
    try { outHeaders.set('location', proxyPath(new URL(location, target))); }
    catch { outHeaders.delete('location'); }
  }

  if (res.destroyed) return;
  const contentType = upstream.headers.get('content-type') || '';
  if (/text\/html|application\/xhtml\+xml/i.test(contentType)) {
    const source = await upstream.text();
    const html = rewriteHtml(source, target);
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

  if (/application\/json|text\/plain/i.test(contentType)) {
    const text = await upstream.text();
    let pageOrigin = target.origin;
    try {
      const ref = mapReferer(req.headers.referer);
      if (ref) pageOrigin = new URL(ref).origin;
    } catch { /* keep default */ }
    const originToken = Buffer.from(pageOrigin, 'utf8').toString('base64url');
    const rewritten = text.replace(/(["'])wss?:\/\/[^"']+\1/gi, (match, quote) => {
      const cleanUrl = match.slice(1, -1);
      if (cleanUrl.includes('localhost')) return match;
      const encoded = Buffer.from(cleanUrl.replace(/^wss:\/\//i, 'https://').replace(/^ws:\/\//i, 'http://')).toString('base64url');
      return `${quote}ws://${req.headers.host}/_ws/${encoded}?o=${originToken}${quote}`;
    });
    if (rewritten !== text) {
      outHeaders.set('content-length', Buffer.byteLength(rewritten));
      res.writeHead(upstream.status, { ...Object.fromEntries(outHeaders), ...(cookies.length ? { 'set-cookie': cookies } : {}) });
      return res.end(rewritten);
    }
    outHeaders.set('content-length', Buffer.byteLength(text));
    res.writeHead(upstream.status, { ...Object.fromEntries(outHeaders), ...(cookies.length ? { 'set-cookie': cookies } : {}) });
    return res.end(text);
  }

  res.writeHead(upstream.status, { ...Object.fromEntries(outHeaders), ...(cookies.length ? { 'set-cookie': cookies } : {}) });
  if (!upstream.body || req.method === 'HEAD') return res.end();
  const downstream = Readable.fromWeb(upstream.body);
  downstream.on('error', () => { if (!res.destroyed) res.destroy(); });
  res.on('error', () => downstream.destroy());
  res.on('close', () => { if (!res.writableFinished) downstream.destroy(); });
  downstream.pipe(res);
}

async function readJsonBody(req, limit = 8192) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('Request body is too large.');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// ---------------------------------------------------------------------------
// Unified Server
// ---------------------------------------------------------------------------

function createServer(options, handler) {
  if (tlsOptions) return https.createServer({ ...tlsOptions, ...options }, handler);
  return http.createServer(options, handler);
}

const server = createServer({ timeout: 0 }, async (req, res) => {
  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); }
  catch { return res.writeHead(400).end('Invalid request.'); }

  const ip = getClientIp(req);
  if (isAuthBanned(ip)) return forbidden(res);

  // ROUTING: Proxy Path
  if (local.pathname.startsWith('/p/') || local.pathname.startsWith('/_ws/')) {
    if (req.method === 'OPTIONS') {
      const preflight = takeToken(`preflight:${ip}`, 30, 60, 300000);
      if (preflight.banned || !preflight.ok) return rateLimited(res, preflight.retryAfter || 1);
      const requestedOrigin = req.headers.origin;
      let allowOrigin = `http://${req.headers.host}`;
      if (requestedOrigin) {
        try {
          const parsedOrigin = new URL(requestedOrigin);
          allowOrigin = requestedOrigin;
        } catch { /* use default */ }
      }
      res.writeHead(204, {
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || '*',
        'Access-Control-Max-Age': '600',
        'Vary': 'Origin',
      });
      return res.end();
    }

    const auth = authenticateProxy(req, local);
    if (!auth) return sendUnauthorized(res, 'Authentication required.');

    const limit = takeToken(`proxy:${auth.session.token}`, 60, 120, 600000);
    if (limit.banned || !limit.ok) return rateLimited(res, limit.retryAfter || 1);

    let target;
    try { target = targetFromRequest(req, local); }
    catch (error) {
      logProxyRouteFailure(req, 400, error.message);
      return res.writeHead(400).end(error.message);
    }
    if (!target) {
      logProxyRouteFailure(req, 404, 'no target token');
      return res.writeHead(404).end('No target is associated with this request.');
    }

    const sessionId = auth.session.token;

    if (auth.source === 'query' && req.method === 'GET') {
      const cleanUrl = new URL(req.url, `http://${HOST}:${PORT}`);
      cleanUrl.searchParams.delete('__k');
      const secure = isLocalhostHost(req) ? (req.socket.encrypted ? '; Secure' : '') : '; Secure';
      const sameSite = secure ? 'None' : 'Lax';
      res.writeHead(302, {
        'Location': cleanUrl.pathname + cleanUrl.search,
        'Set-Cookie': `__pv_proxy=${sessionId}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=86400${secure}`,
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Request-Id': crypto.randomUUID(),
      });
      return res.end();
    }

    const requestStarted = Date.now();
    let responseBytes = 0;
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);
    res.write = (chunk, encoding, callback) => {
      const size = responseChunkSize(chunk, encoding);
      responseBytes += size;
      if (!checkBytes(sessionId, size)) { res.destroy(); return false; }
      return originalWrite(chunk, encoding, callback);
    };
    res.end = (chunk, encoding, callback) => {
      if (chunk) {
        const size = responseChunkSize(chunk, encoding);
        responseBytes += size;
        checkBytes(sessionId, size);
      }
      return originalEnd(chunk, encoding, callback);
    };
    res.once('finish', () => {
      if (PROXY_LOG_MODE === 'all' || res.statusCode >= 400) {
        const type = res.proxyContentType || 'no-content-type';
        logProxy(req.method, target, res.statusCode, `${Date.now() - requestStarted}ms ${responseBytes}B ${type} sid=${sessionId.slice(0, 8)}${res.proxyError ? ` error=${res.proxyError}` : ''}`);
      }
    });

    return proxyRequest(req, res, target, sessionId).catch((error) => {
      console.error(`[proxy] ${proxyHostname(target.hostname)} -> ${error.name || 'Error'}${error.cause?.code ? `/${error.cause.code}` : ''} sid=${sessionId.slice(0, 8)}`);
      res.proxyError = `${error.name || 'Error'}${error.cause?.code ? `/${error.cause.code}` : ''}`;
      let allowOrigin = `http://${req.headers.host}`;
      if (req.headers.origin) allowOrigin = req.headers.origin;
      if (!res.headersSent && !res.destroyed) res.writeHead(error.name === 'TimeoutError' ? 504 : 502, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': '*',
        'X-Request-Id': crypto.randomUUID(),
      });
      if (!res.destroyed) res.end(error.message || 'The website could not be loaded through the local proxy.');
    });
  }

  // ROUTING: Launcher
  if (req.method === 'GET' && local.pathname === '/' && local.searchParams.has('k')) {
    const provided = local.searchParams.get('k') || '';
    if (!timingSafeEqualStr(provided, PROXY_TOKEN)) {
      console.log(`[auth] master token rejected ip=${ip}`);
      recordAuthFailure(ip);
      return sendUnauthorized(res, 'Invalid launcher token.');
    }
    const authSession = createSession(req);
    if (!authSession) return serviceUnavailable(res, 'Too many active sessions.');
    console.log(`[auth] session created ip=${ip} sid=${authSession.token.slice(0, 8)}`);
    const secure = req.socket.encrypted ? '; Secure' : '';
    res.writeHead(302, {
      'Location': '/',
      'Set-Cookie': `__pv_auth=${authSession.token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secure}`,
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Request-Id': crypto.randomUUID(),
    });
    return res.end();
  }

  if (req.method === 'POST' && local.pathname === '/logout') {
    const authSession = getSessionFromCookie(req.headers.cookie, '__pv_auth');
    if (authSession) {
      sessions.delete(authSession.token);
      await stopStream(authSession.token);
      console.log(`[auth] logout ip=${ip} sid=${authSession.token.slice(0, 8)}`);
    }
    res.writeHead(204, {
      'Set-Cookie': '__pv_auth=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
      'Cache-Control': 'no-store',
      'X-Request-Id': crypto.randomUUID(),
    });
    return res.end();
  }

  const authSession = getSessionFromCookie(req.headers.cookie, '__pv_auth');
  if (!authSession) {
    if (!local.pathname.match(/\.(ico|png|jpg|css|js)$/)) {
      console.log(`[auth] unauthenticated ${req.method} ${local.pathname} ip=${ip}`);
    }
    return sendUnauthorized(res, 'Authentication required.');
  }

  const launcherLimit = takeToken(`launcher:${authSession.token}`, 20, 40, 300000);
  if (launcherLimit.banned || !launcherLimit.ok) return rateLimited(res, launcherLimit.retryAfter || 1);

  if (req.method === 'GET' && (local.pathname === '/' || local.pathname === '/index.html')) {
    try {
      let page = fs.readFileSync(PAGE_PATH, 'utf8').replaceAll('__PROXY_PORT__', String(PORT));
      page = page.replace('__PV_SESSION_JSON__', JSON.stringify(authSession.token));
      return send(res, 200, page, 'text/html; charset=utf-8');
    } catch { return send(res, 500, 'Could not read index.html.'); }
  }

  if (req.method === 'GET' && local.pathname === '/stream/logs') {
    if (!DEBUG) return send(res, 404, 'Not found.');
    let logs = 'No streamed-browser diagnostics yet. Start a streamed session first.';
    try { logs = fs.readFileSync(STREAM_DIAGNOSTICS_PATH, 'utf8'); } catch { /* no session started */ }
    return send(res, 200, logs, 'text/plain; charset=utf-8');
  }

  if (req.method === 'GET' && local.pathname === '/favicon.ico') {
    res.writeHead(204, { 'Cache-Control': 'no-store' });
    return res.end();
  }

  if (req.method === 'POST' && local.pathname === '/stream/start') {
    if (req.headers['content-type']?.split(';')[0] !== 'application/json') return send(res, 415, 'Expected JSON.');
    try {
      const body = await readJsonBody(req);
      const target = new URL(body.url);
      if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS websites are supported.');
      if (streamSessions.size >= MAX_SESSIONS) return serviceUnavailable(res, 'Too many streamed sessions.');
      await startStream(authSession.token, target);
      return send(res, 202, JSON.stringify({ ok: true }), 'application/json; charset=utf-8');
    } catch (error) {
      console.error(`[stream] start failed: ${error.name || 'Error'}${error.cause?.code ? `/${error.cause.code}` : ''} sid=${authSession.token.slice(0, 8)}`);
      return send(res, 502, error.message || 'Could not start the hidden browser.');
    }
  }

  if (req.method === 'POST' && local.pathname === '/stream/stop') {
    if (!streamSessions.has(authSession.token)) return send(res, 404, 'No stream for this session.');
    await stopStream(authSession.token);
    return send(res, 200, 'Stopped.');
  }

  if (req.method === 'POST' && local.pathname === '/stream/resize') {
    const session = streamSessions.get(authSession.token);
    if (!session) return send(res, 404, 'No stream for this session.');
    try {
      const { width, height } = await readJsonBody(req);
      const nextWidth = Math.max(320, Math.min(3840, Math.round(Number(width) || 0)));
      const nextHeight = Math.max(240, Math.min(2160, Math.round(Number(height) || 0)));
      const resize = session.resizeChain.then(async () => {
        if (streamSessions.get(authSession.token) !== session) throw new Error('The hidden browser session changed during resize.');
        if (session.width !== nextWidth || session.height !== nextHeight) {
          streamDiagnostic(authSession.token, `viewer resize ${session.width}x${session.height} -> ${nextWidth}x${nextHeight}`);
          await cdpCommand(session, 'Emulation.setDeviceMetricsOverride', { width: nextWidth, height: nextHeight, deviceScaleFactor: 1, mobile: false });
          session.width = nextWidth;
          session.height = nextHeight;
          session.reportedState = null;
        }
      });
      session.resizeChain = resize.catch(() => {});
      await resize;
      return send(res, 200, JSON.stringify({ width: nextWidth, height: nextHeight }), 'application/json; charset=utf-8');
    } catch (error) {
      console.error(`[stream] resize failed: ${error.message || error}`);
      return send(res, 502, error.message || 'Could not resize hidden browser.');
    }
  }

  if (req.method === 'GET' && local.pathname === '/stream/state') {
    const session = streamSessions.get(authSession.token);
    if (!session) return send(res, 404, 'No stream for this session.');
    try {
      const result = await cdpCommand(session, 'Runtime.evaluate', {
        expression: '({ width: innerWidth, height: innerHeight, pointerLocked: Boolean(document.pointerLockElement), lockMode: window.__streamLockMode || null, fullscreen: Boolean(document.fullscreenElement) })', returnByValue: true,
      });
      const state = result.result?.value || {};
      const pointerLocked = Boolean(state.pointerLocked || session.observedPointerLock);
      const lockMode = state.lockMode || (pointerLocked ? 'native' : null);
      const fullscreen = Boolean(state.fullscreen || session.observedFullscreen);
      const stateKey = `${Number(state.width) || session.width}x${Number(state.height) || session.height} lock=${pointerLocked}${lockMode ? `/${lockMode}` : ''} fullscreen=${fullscreen}`;
      if (session.reportedState !== stateKey) {
        session.reportedState = stateKey;
        streamDiagnostic(authSession.token, `hidden viewport=${stateKey}`);
      }
      return send(res, 200, JSON.stringify({
        width: Math.max(1, Number(state.width) || session.width),
        height: Math.max(1, Number(state.height) || session.height),
        pointerLocked,
        lockMode,
        fullscreen,
        frames: session.frames,
      }), 'application/json; charset=utf-8');
    } catch (error) {
      return send(res, 502, error.message || 'Could not read game input state.');
    }
  }

  if (req.method === 'POST' && local.pathname === '/stream/input') {
    const session = streamSessions.get(authSession.token);
    if (!session) return send(res, 404, 'No stream for this session.');
    if (req.headers['content-type']?.split(';')[0] !== 'application/json') return send(res, 415, 'Expected JSON.');
    try {
      const body = await readJsonBody(req, 64 * 1024);
      const events = Array.isArray(body.events) ? body.events : [body];
      for (const event of events.slice(0, 1000)) dispatchStreamInput(session, event);
      return send(res, 204, '');
    } catch (error) {
      console.error(`[stream] input failed: ${error.name || 'Error'} ${error.message || ''}`);
      return send(res, 502, error.message || 'Could not send input to hidden Chrome.');
    }
  }

  if (req.method === 'GET' && local.pathname === '/stream') {
    const session = streamSessions.get(authSession.token);
    if (!session) return send(res, 404, 'No stream for this session.');
    res.writeHead(200, {
      'Content-Type': 'multipart/x-mixed-replace; boundary=frame',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Connection': 'keep-alive',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    session.clients.add(res);
    res.once('close', () => session.clients.delete(res));
    if (session.latestJpeg) {
      const { latestJpeg } = session;
      res.write(frameChunk(latestJpeg));
      setTimeout(() => { if (!res.destroyed) res.write(frameChunk(latestJpeg)); }, 80);
    }
    return;
  }

  return send(res, 404, 'Not found.');
});

async function relayUpgrade(req, client, head, target, originOverride, sessionId, extraHeaders) {
  if (client.parser) client.parser = null;
  client.setKeepAlive(true, 30000);

  const secure = target.protocol === 'wss:';
  const port = Number(target.port) || (secure ? 443 : 80);
  const upstream = secure
    ? tls.connect({ host: target.hostname, port, servername: target.hostname })
    : net.connect({ host: target.hostname, port });

  client.setNoDelay(true);
  upstream.setNoDelay(true);

  upstream.once(secure ? 'secureConnect' : 'connect', () => {
    upstream.setKeepAlive(true, 30000);
    const lines = [`${req.method} ${target.pathname}${target.search} HTTP/${req.httpVersion}`];
    let hasOrigin = false;
    const stripForwarded = !TRUST_FORWARDED;
    for (const [name, value] of Object.entries(req.headers)) {
      const lower = name.toLowerCase();
      if (lower === 'host') { lines.push(`Host: ${target.host}`); continue; }
      if (lower === 'origin') { hasOrigin = true; lines.push(`Origin: ${originOverride || target.origin.replace(/^wss?:/i, secure ? 'https:' : 'http:')}`); continue; }
      if (lower === 'cookie') {
        const cleaned = stripProxyCookies(value);
        if (cleaned) lines.push(`Cookie: ${cleaned}`);
        continue;
      }
      if (stripForwarded && ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'forwarded', 'x-real-ip'].includes(lower)) continue;
      if (value) lines.push(`${name}: ${Array.isArray(value) ? value.join(', ') : value}`);
    }
    if (stripForwarded) {
      lines.push(`X-Forwarded-For: ${getClientIp(req)}`);
      lines.push(`X-Forwarded-Proto: ${req.socket.encrypted ? 'https' : 'http'}`);
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

    if (!/^HTTP\/1\.[01] 101\b/m.test(handshake)) {
      const status = handshake.match(/^HTTP\/1\.[01] (\d{3})/)?.[1] || 'UNKNOWN';
      if (PROXY_LOG_MODE === 'all' || Number(status) >= 400) logProxy('WS', target, status, `handshake sid=${sessionId.slice(0, 8)}`);
      client.write(responseBuffer);
      client.end();
      upstream.destroy();
      return;
    }

    if (PROXY_LOG_MODE === 'all') logProxy('WS', target, '101', `connected sid=${sessionId.slice(0, 8)}`);

    if (extraHeaders && Object.keys(extraHeaders).length) {
      const extra = '\r\n' + Object.entries(extraHeaders).map(([k, v]) => `${k}: ${v}`).join('\r\n');
      const newBuffer = Buffer.concat([
        responseBuffer.subarray(0, end),
        Buffer.from(extra, 'latin1'),
        responseBuffer.subarray(end),
      ]);
      client.write(newBuffer);
    } else {
      client.write(responseBuffer);
    }
    upstream.removeListener('data', onUpstreamData);

    if (target.hostname.startsWith('party.')) {
      const pageHost = proxyHostname(target.hostname.replace(/^party\./, ''));
      const needle = Buffer.from([0xa2, 0x69, 0x70, 0xd9, 0x20]);
      let tail = Buffer.alloc(0);
      upstream.on('data', (chunk) => {
        const combined = Buffer.concat([tail, chunk]);
        let idx = 0;
        while ((idx = combined.indexOf(needle, idx)) !== -1) {
          const hex = combined.slice(idx + needle.length, idx + needle.length + 32).toString('ascii');
          if (/^[0-9a-f]{32}$/.test(hex)) {
            lastMatchIpByPageHost.set(`${sessionId}:${pageHost}`, hex);
            console.log(`[proxy] captured match ip ${hex.slice(0, 8)}... sid=${sessionId.slice(0, 8)}`);
          }
          idx += needle.length;
        }
        tail = combined.slice(-80);
      });
    }

    upstream.pipe(client);
  };

  upstream.on('data', onUpstreamData);
  upstream.on('error', (error) => {
    logProxy('WS', target, error.cause?.code || error.code || error.name || 'ERROR', `upstream failed sid=${sessionId.slice(0, 8)}`);
    client.destroy();
  });
  client.on('error', () => upstream.destroy());
}

server.on('upgrade', async (req, client, head) => {
  let local;
  try { local = new URL(req.url, `http://${HOST}:${PORT}`); }
  catch { client.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return client.destroy(); }

  const ip = getClientIp(req);
  if (isAuthBanned(ip)) {
    client.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }

  const auth = authenticateProxy(req, local);
  if (!auth) {
    console.log(`[auth] proxy WS unauthenticated ip=${ip}`);
    client.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }

  const limit = takeToken(`proxy:${auth.session.token}`, 60, 120, 600000);
  if (limit.banned || !limit.ok) {
    client.write(`HTTP/1.1 429 Too Many Requests\r\nRetry-After: ${limit.retryAfter || 1}\r\nConnection: close\r\n\r\n`);
    return client.destroy();
  }

  if (auth.session.wsCount >= MAX_WS_PER_SESSION) {
    client.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }

  const sessionId = auth.session.token;
  let target;
  let originForUpgrade;
  try {
    const match = local.pathname.match(/^\/_ws\/([A-Za-z0-9_-]+)(\/.*)?$/);
    if (match) {
      target = decodeTarget(match[1]);
      if (match[2]) target.pathname = match[2];
      target.protocol = target.protocol === 'https:' ? 'wss:' : 'ws:';
      const o = local.searchParams.get('o');
      if (o) {
        try { originForUpgrade = Buffer.from(o, 'base64url').toString('utf8'); } catch { /* keep undefined */ }
      }
      await validatePublicTarget(target);
    } else if (local.pathname === '/ws') {
      let pageOrigin;
      if (req.headers.referer) {
        const refererPath = new URL(req.headers.referer).pathname;
        const pageMatch = refererPath.match(/^\/p\/([A-Za-z0-9_-]+)(\/.*)?$/);
        if (pageMatch) pageOrigin = decodeTarget(pageMatch[1]).origin;
      }
      if (!pageOrigin) throw new Error('Unknown page origin for /ws.');

      const page = new URL(pageOrigin);
      const cleanSearch = stripKParam(local.search);

      const storedMatchIp = lastMatchIpByPageHost.get(`${sessionId}:${proxyHostname(page.hostname)}`);
      if (storedMatchIp && local.pathname === '/ws' && cleanSearch) {
        target = new URL(`wss://ip_${storedMatchIp}.${page.hostname}${local.pathname}${cleanSearch}`);
        originForUpgrade = page.origin;
      } else {
        let wsHost = page.host;
        try { await lookup(`party.${page.hostname}`); wsHost = `party.${page.hostname}`; } catch { /* no party host */ }
        target = new URL(`${page.protocol === 'https:' ? 'wss:' : 'ws:'}//${wsHost}${local.pathname}${cleanSearch}`);
        originForUpgrade = page.origin;
      }
      await validatePublicTarget(target);
    } else {
      throw new Error('Unknown WS path.');
    }
  } catch (error) {
    console.log(`[proxy] WS upgrade rejected: ${error.message || error} sid=${sessionId.slice(0, 8)}`);
    client.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return client.destroy();
  }

  auth.session.wsCount = (auth.session.wsCount || 0) + 1;
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    auth.session.wsCount = Math.max(0, (auth.session.wsCount || 1) - 1);
  };
  client.once('close', release);
  const startTime = Date.now();

  const secure = isLocalhostHost(req) ? (req.socket.encrypted ? '; Secure' : '') : '; Secure';
  const sameSite = secure ? 'None' : 'Lax';
  const extraHeaders = auth.source === 'query'
    ? { 'Set-Cookie': `__pv_proxy=${sessionId}; HttpOnly; SameSite=${sameSite}; Path=/; Max-Age=86400${secure}` }
    : null;

  await relayUpgrade(req, client, head, target, originForUpgrade, sessionId, extraHeaders);
  client.once('close', () => {
    if (PROXY_LOG_MODE === 'all') console.log(`[proxy] WS closed sid=${sessionId.slice(0, 8)} duration=${Date.now() - startTime}ms`);
  });
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

if (BIND_ADDRESS !== '127.0.0.1' && !process.env.PROXY_TOKEN) {
  console.error('Refusing to bind to a non-loopback address (BIND_ADDRESS=' + BIND_ADDRESS + ') without PROXY_TOKEN env var set.');
  process.exit(1);
}

if (process.env.TLS_CERT_PATH && process.env.TLS_KEY_PATH) {
  try {
    tlsOptions = {
      cert: fs.readFileSync(process.env.TLS_CERT_PATH),
      key: fs.readFileSync(process.env.TLS_KEY_PATH),
    };
  } catch (error) {
    console.error(`Could not read TLS cert/key: ${error.message}`);
    process.exit(1);
  }
}

PROXY_TOKEN = loadOrCreateToken();

try {
  fs.writeFileSync(STREAM_DIAGNOSTICS_PATH, `Stream diagnostics started ${new Date().toISOString()}\n`, 'utf8');
} catch { /* best effort */ }

setInterval(pruneSessions, 60 * 1000).unref();
setInterval(cleanupRateLimits, 60 * 1000).unref();

server.listen(PORT, BIND_ADDRESS, () => {
  const scheme = tlsOptions ? 'https' : 'http';
  console.log(`Launcher: ${scheme}://localhost:${PORT}/?k=<token>`);
  console.log(`Token file: ${TOKEN_PATH}`);
  console.log(`Bind address: ${BIND_ADDRESS}${BIND_ADDRESS === '127.0.0.1' ? ' (loopback only)' : ' (non-loopback; PROXY_TOKEN required)'}`);
  console.log('All services are running on this single port.');
});
server.on('error', (error) => { console.error(error.message); process.exitCode = 1; });

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    stopAllStreams().finally(() => process.exit(0));
  });
}