import express from 'express';
import * as cheerio from 'cheerio';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.raw({ type: '*/*', limit: '10mb' }));

// ─── Encoding helpers ────────────────────────────────────
const b64e = (s) => Buffer.from(s, 'utf8').toString('base64url');
const b64d = (s) => Buffer.from(s, 'base64url').toString('utf8');

function toProxyPath(absUrl) {
  try {
    const u = new URL(absUrl);
    return '/p/' + b64e(u.origin) + u.pathname + u.search + u.hash;
  } catch { return absUrl; }
}

// ─── Header sanitization ─────────────────────────────────
const REQ_BLOCK = new Set([
  'host','connection','content-length','transfer-encoding','upgrade',
  'accept-encoding','referer','cookie','origin',
]);

const RES_BLOCK = new Set([
  'content-encoding','content-length','transfer-encoding','connection',
  'content-security-policy','content-security-policy-report-only',
  'x-frame-options','strict-transport-security','set-cookie','set-cookie2',
  'report-to','nel','permissions-policy','cross-origin-embedder-policy',
  'cross-origin-opener-policy','cross-origin-resource-policy',
]);

function cleanReqHeaders(h) {
  const out = { 'accept-encoding': 'identity' }; // force uncompressed so we can rewrite
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase();
    if (REQ_BLOCK.has(lk)) continue;
    if (lk.startsWith('proxy-') || lk.startsWith('sec-')) continue;
    out[k] = v;
  }
  return out;
}

// ─── HTML rewriting ──────────────────────────────────────
function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html);

  // Resolve against <base> if present, then remove it
  const baseTag = $('base[href]').attr('href');
  const effectiveBase = baseTag ? new URL(baseTag, baseUrl).href : baseUrl;
  $('base').remove();

  // Integrity/crossorigin will be wrong after rewriting
  $('[integrity]').removeAttr('integrity');
  $('[crossorigin]').removeAttr('crossorigin');

  const rewriteOne = (url) => {
    if (!url) return url;
    const s = String(url).trim();
    if (!s) return url;
    if (/^(data:|javascript:|mailto:|tel:|blob:|about:|#)/i.test(s)) return url;
    try { return toProxyPath(new URL(s, effectiveBase).href); }
    catch { return url; }
  };

  const rewriteSrcset = (val) => val.split(',').map(part => {
    const bits = part.trim().split(/\s+/);
    const u = bits.shift();
    return rewriteOne(u) + (bits.length ? ' ' + bits.join(' ') : '');
  }).join(', ');

  const ATTRS = ['src','href','action','poster','data-src','data-href','formaction'];
  for (const attr of ATTRS) {
    $(`[${attr}]`).each((_, el) => {
      const v = $(el).attr(attr);
      if (v != null) $(el).attr(attr, rewriteOne(v));
    });
  }
  $('[srcset]').each((_, el) => {
    const v = $(el).attr('srcset');
    if (v) $(el).attr('srcset', rewriteSrcset(v));
  });

  // Inline <style> url() rewriting
  $('style').each((_, el) => {
    const css = $(el).html() || '';
    $(el).html(css.replace(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/g, (m, q, u) => {
      return `url(${q}${rewriteOne(u)}${q})`;
    }));
  });

  // Expose target origin to client-side JS (no $io query param anywhere)
  const origin = new URL(baseUrl).origin;
  const originB64 = b64e(origin);
  const injected = `<script>(function(){
    window.__P_ORIGIN__     = ${JSON.stringify(origin)};
    window.__P_ORIGIN_B64__ = ${JSON.stringify(originB64)};
    window.__P_BASE__       = ${JSON.stringify(baseUrl)};
    window.__P_WRAP__ = function(u){
      try {
        var a = new URL(u, ${JSON.stringify(baseUrl)});
        return '/p/' + ${JSON.stringify(originB64)} + a.pathname + a.search + a.hash;
      } catch(e){ return u; }
    };
  })();</script>`;
  if ($('head').length) $('head').prepend(injected);
  else $.root().prepend(injected);

  return $.html();
}

// ─── Main proxy handler ──────────────────────────────────
app.use(async (req, res) => {
  if (!req.path.startsWith('/p/')) {
    return res.status(404).send(
      'Proxy is up. Use /p/<base64url-origin>/<path> — e.g. /p/aHR0cHM6Ly9leGFtcGxlLmNvbQ==/'
    );
  }

  // Parse from originalUrl so query string survives
  const raw = req.originalUrl.slice(3); // strip "/p/"
  const slash = raw.indexOf('/');
  const originB64 = slash < 0 ? raw : raw.slice(0, slash);
  const rest      = slash < 0 ? '/' : raw.slice(slash);

  let origin;
  try { origin = b64d(originB64); } catch { return res.status(400).send('Bad origin b64'); }
  if (!/^https?:\/\//i.test(origin)) return res.status(400).send('Bad origin');

  const targetUrl = origin + rest;

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method,
      headers: cleanReqHeaders(req.headers),
      body: ['GET','HEAD'].includes(req.method) ? undefined : req.body,
      redirect: 'manual',
    });

    // Rewrite redirects through the proxy
    if (upstream.status >= 300 && upstream.status < 400) {
      const loc = upstream.headers.get('location');
      res.status(upstream.status);
      if (loc) {
        const abs = new URL(loc, targetUrl).href;
        res.setHeader('location', toProxyPath(abs));
      }
      return res.end();
    }

    // Copy safe response headers
    for (const [k, v] of upstream.headers) {
      if (!RES_BLOCK.has(k.toLowerCase())) res.setHeader(k, v);
    }

    const ct = (upstream.headers.get('content-type') || '').toLowerCase();

    if (ct.includes('text/html')) {
      const html = await upstream.text();
      res.setHeader('content-type', 'text/html; charset=utf-8');
      return res.send(rewriteHtml(html, targetUrl));
    }

    // Everything else: pass through raw bytes
    const buf = Buffer.from(await upstream.arrayBuffer());
    return res.send(buf);

  } catch (e) {
    console.error('[proxy]', targetUrl, e.message);
    res.status(502).send('Proxy error: ' + e.message);
  }
});

app.listen(PORT, () => console.log(`Proxy listening on :${PORT}`));
