/**
 * ════════════════════════════════════════════════════════════════
 * MChat Proxy — fetches a page server-side and returns sanitized
 * HTML + metadata for the browser panel, which renders it inside a
 * sandboxed <iframe srcdoc="..."> (no allow-scripts). This is what
 * avoids CSP / X-Frame-Options blocking entirely: the target site's
 * CSP headers only govern requests made *by a browser rendering that
 * page*, and here the page is never rendered as a page — it's
 * fetched as data, then handed to an isolated iframe document.
 *
 * <style> tags are KEPT (not stripped) — the frontend renders inside
 * a sandboxed iframe, so the target page's CSS is fully isolated and
 * can't collide with MChat's own styles. Stripping it was what made
 * pages like Google render as unstyled black circles instead of icons.
 *
 * <script> tags, inline on*= handlers, and javascript: URLs are still
 * stripped as defense-in-depth, even though the iframe sandbox (no
 * allow-scripts) already blocks execution on its own.
 *
 * Response shape (consumed by index.html's loadBrowserPage()):
 *   { error, url, contentType, status, size, content, metadata,
 *     charset, cached }
 * ════════════════════════════════════════════════════════════════
 */

'use strict';

const CONFIG = {
  MAX_CONTENT_SIZE: 5 * 1024 * 1024, // 5MB
  REQUEST_TIMEOUT: 15000,
  CACHE_TTL: 30 * 60 * 1000,
  CACHE_MAX_ENTRIES: 100,
  MAX_REDIRECTS: 5,
  ALLOWED_PROTOCOLS: ['http:', 'https:'],
  USER_AGENT: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  MAX_HTML_RETURNED: 150000,
  // Best-effort only (resets on cold start) — see RateLimiter note below.
  REQUESTS_PER_MINUTE: 40,
};

// ═══════════════════════════════════════════════════════════
// CACHE
// ═══════════════════════════════════════════════════════════

class CacheManager {
  constructor() { this.cache = new Map(); }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > CONFIG.CACHE_TTL) { this.cache.delete(key); return null; }
    return entry.data;
  }

  set(key, data) {
    this.cache.set(key, { data, timestamp: Date.now() });
    if (this.cache.size > CONFIG.CACHE_MAX_ENTRIES) {
      this.cache.delete(this.cache.keys().next().value);
    }
  }
}

const cache = new CacheManager();

// ═══════════════════════════════════════════════════════════
// RATE LIMITER (best-effort — see api/chat.js for the same pattern)
// ═══════════════════════════════════════════════════════════
//
// Resets on cold start / new serverless instance, so this is not a
// hard global limit. It exists to give a friendly message instead of
// hammering the target site (and this function's own timeout budget)
// during a burst of clicks from the same tab.

class RateLimiter {
  constructor() { this.requests = []; }

  isAllowed(clientId) {
    const now = Date.now();
    const cutoff = now - 60000;
    this.requests = this.requests.filter(r => r.time > cutoff);
    const mine = this.requests.filter(r => r.clientId === clientId);
    if (mine.length >= CONFIG.REQUESTS_PER_MINUTE) return false;
    this.requests.push({ clientId, time: now });
    return true;
  }
}

const rateLimiter = new RateLimiter();

// ═══════════════════════════════════════════════════════════
// LOGGER
// ═══════════════════════════════════════════════════════════

class Logger {
  static log(level, message, data = {}) { console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...data })); }
  static info(message, data) { this.log('INFO', message, data); }
  static warn(message, data) { this.log('WARN', message, data); }
  static error(message, data) { this.log('ERROR', message, data); }
}

// ═══════════════════════════════════════════════════════════
// URL VALIDATION
// ═══════════════════════════════════════════════════════════
//
// Blocks loopback / private / link-local ranges by exact octet parsing
// (not substring matching — "expo10.info" is not "10.x.x.x"). This is a
// reasonable guard for a single-user hobby proxy; it does not defend
// against DNS-rebinding attacks (resolving a public hostname to a
// private IP after this check runs), which would need actual DNS
// resolution at fetch time. Not a concern for this project's threat model.

class URLValidator {
  static isBlockedHost(hostname) {
    const h = hostname.toLowerCase().replace(/\.$/, '');
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
    if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;

    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (m) {
      const [a, b] = [Number(m[1]), Number(m[2])];
      if (a === 127) return true;                    // loopback
      if (a === 10) return true;                      // 10.0.0.0/8
      if (a === 0) return true;                        // 0.0.0.0/8
      if (a === 169 && b === 254) return true;         // link-local
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
      if (a === 192 && b === 168) return true;         // 192.168.0.0/16
    }
    return false;
  }

  static validate(urlString) {
    let url;
    try { url = new URL(urlString); } catch { throw new Error('Invalid URL'); }

    if (!CONFIG.ALLOWED_PROTOCOLS.includes(url.protocol)) {
      throw new Error(`Unsupported protocol: ${url.protocol}`);
    }
    if (!url.hostname) throw new Error('Invalid URL: no hostname');
    if (this.isBlockedHost(url.hostname)) throw new Error('Requests to local/private addresses are not allowed');

    return url;
  }
}

// ═══════════════════════════════════════════════════════════
// CHARSET DETECTION & DECODING
// ═══════════════════════════════════════════════════════════
//
// The old version always did Buffer.toString('utf-8'), which silently
// mangles any page served in windows-1251, koi8-r, iso-8859-1, etc —
// still common on older/regional (including many .ru) sites. We sniff
// the real encoding the same way a browser does: Content-Type header
// first, then a <meta charset> / <meta http-equiv content=...charset=...>
// look inside the raw bytes, falling back to utf-8.

class CharsetResolver {
  static fromContentType(contentType) {
    const m = /charset=([^;]+)/i.exec(contentType || '');
    return m ? m[1].trim().replace(/["']/g, '').toLowerCase() : null;
  }

  static fromHtmlBytes(buffer) {
    // Charset declarations always live in the first ~1KB of well-formed
    // HTML, and are always ASCII-safe there — latin1 is a safe enough
    // lens to read them regardless of the real encoding.
    const head = buffer.subarray(0, 2048).toString('latin1');
    let m = /<meta[^>]+charset\s*=\s*["']?([a-zA-Z0-9_-]+)/i.exec(head);
    if (m) return m[1].toLowerCase();
    m = /<meta[^>]+http-equiv=["']content-type["'][^>]*content=["'][^"']*charset=([a-zA-Z0-9_-]+)/i.exec(head);
    if (m) return m[1].toLowerCase();
    return null;
  }

  static normalize(charset) {
    if (!charset) return 'utf-8';
    const c = charset.toLowerCase();
    // A handful of common aliases TextDecoder doesn't always accept as-is.
    const aliases = { 'win-1251': 'windows-1251', 'cp1251': 'windows-1251', 'cp-1251': 'windows-1251', 'win1251': 'windows-1251' };
    return aliases[c] || c;
  }

  static decode(buffer, contentType) {
    const declared = this.normalize(this.fromContentType(contentType) || this.fromHtmlBytes(buffer));
    try {
      return { text: new TextDecoder(declared, { fatal: false }).decode(buffer), charset: declared };
    } catch {
      // Unknown/unsupported label (TextDecoder throws RangeError) — fall
      // back to utf-8 rather than failing the whole page load.
      return { text: new TextDecoder('utf-8', { fatal: false }).decode(buffer), charset: 'utf-8 (fallback)' };
    }
  }
}

// ═══════════════════════════════════════════════════════════
// CONTENT FETCHING
// ═══════════════════════════════════════════════════════════

class ContentProcessor {
  // Turns Node/undici's generic "fetch failed" into something diagnosable
  // by pulling the real reason out of error.cause (DNS, TLS, connection
  // reset, etc). Cloudflare/WAF-style blocks of datacenter IPs usually
  // surface here as ECONNRESET or "other side closed" — that specific
  // signature means the target is actively rejecting server-side fetches
  // and no amount of header-spoofing from this proxy will fix it; the
  // "Open in real browser" fallback is the correct answer for those sites.
  static describeFetchError(error) {
    const cause = error?.cause;
    const causeMsg = cause?.message || cause?.code || (cause ? String(cause) : null);
    if (causeMsg) return `${error.message} (${causeMsg})`;
    return error.message;
  }

  static async fetchContent(targetUrl, redirectCount = 0) {
    if (redirectCount > CONFIG.MAX_REDIRECTS) throw new Error('Too many redirects');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    try {
      const response = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'follow',
        headers: {
          'User-Agent': CONFIG.USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
          'Accept-Encoding': 'gzip, deflate, br',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Upgrade-Insecure-Requests': '1',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Re-validate the *final* URL after redirects — fetch's redirect:'follow'
      // can land somewhere that would have failed our own SSRF check.
      URLValidator.validate(response.url);

      if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);

      const contentLength = response.headers.get('content-length');
      if (contentLength && Number(contentLength) > CONFIG.MAX_CONTENT_SIZE) {
        throw new Error(`Content too large: ${contentLength} bytes`);
      }

      const arrayBuffer = await response.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      if (buffer.byteLength > CONFIG.MAX_CONTENT_SIZE) {
        throw new Error(`Content too large: ${buffer.byteLength} bytes`);
      }

      const contentType = response.headers.get('content-type') || '';
      const isText = contentType.includes('text/') || contentType.includes('xml') || contentType.includes('json') || contentType === '';
      const { text, charset } = isText
        ? CharsetResolver.decode(buffer, contentType)
        : { text: '', charset: null };

      return {
        content: text,
        raw: buffer,
        contentType,
        charset,
        status: response.status,
        url: response.url,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') throw new Error('Request timed out (15s) — site may be slow or unreachable from Vercel');
      throw new Error(this.describeFetchError(error));
    }
  }

  static extractMetadata(html, url) {
    const metadata = { title: '', description: '', image: '', url };
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    if (titleMatch) metadata.title = titleMatch[1].trim();

    const ogTitle = html.match(/<meta\s+property=["']og:title["']\s+content=["']([^"']+)["']/i);
    if (ogTitle) metadata.title = ogTitle[1];

    const desc = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
    if (desc) metadata.description = desc[1].trim();

    const ogImage = html.match(/<meta\s+property=["']og:image["']\s+content=["']([^"']+)["']/i);
    if (ogImage) metadata.image = ogImage[1];

    return metadata;
  }

  // <style> is intentionally KEPT — see header comment. Everything that
  // could execute code is still stripped as defense-in-depth on top of
  // the iframe sandbox:
  //   - <script>...</script>
  //   - on*="..."/on*='...' inline event handlers
  //   - <iframe> (no proxied nested iframes)
  //   - javascript: URLs in href/src
  //   - <meta http-equiv="refresh"> (would otherwise silently redirect
  //     the sandboxed iframe out from under the user)
  static sanitizeHTML(html) {
    let out = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    out = out.replace(/\son\w+\s*=\s*"[^"]*"/gi, '');
    out = out.replace(/\son\w+\s*=\s*'[^']*'/gi, '');
    out = out.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    out = out.replace(/(\s(?:href|src))\s*=\s*(["'])\s*javascript:[^"']*\2/gi, '$1=$2#$2');
    out = out.replace(/<meta[^>]+http-equiv=["']refresh["'][^>]*>/gi, '');
    if (out.length > CONFIG.MAX_HTML_RETURNED) out = out.slice(0, CONFIG.MAX_HTML_RETURNED) + '\n<!-- content truncated -->';
    return out;
  }
}

// ═══════════════════════════════════════════════════════════
// RESPONSE WRITER
// ═══════════════════════════════════════════════════════════

class ResponseWriter {
  static sendJSON(res, data, status = 200) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(status).json(data);
  }
  static sendError(res, message, status = 400) { this.sendJSON(res, { error: true, message }, status); }
  static sendSuccess(res, data) { this.sendJSON(res, { error: false, ...data }, 200); }
}

// ═══════════════════════════════════════════════════════════
// MAIN HANDLER
// ═══════════════════════════════════════════════════════════

async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.status(200).end();
    return;
  }

  if (!['POST', 'GET'].includes(req.method)) {
    ResponseWriter.sendError(res, 'Method not allowed', 405);
    return;
  }

  const clientId = req.headers['x-client-id'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  if (!rateLimiter.isAllowed(clientId)) {
    ResponseWriter.sendError(res, `Too many requests. Max ${CONFIG.REQUESTS_PER_MINUTE} per minute — please wait a moment.`, 429);
    return;
  }

  try {
    let targetURL;
    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      targetURL = body?.url;
    } else {
      targetURL = req.query.url;
    }

    if (!targetURL) { ResponseWriter.sendError(res, 'URL parameter required'); return; }

    try {
      URLValidator.validate(targetURL);
    } catch (validationError) {
      ResponseWriter.sendError(res, validationError.message);
      return;
    }

    const cacheKey = `proxy:${targetURL}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      ResponseWriter.sendSuccess(res, { ...cached, cached: true });
      return;
    }

    let fetched;
    try {
      fetched = await ContentProcessor.fetchContent(targetURL);
    } catch (fetchError) {
      Logger.error('Proxy fetch failed', { url: targetURL, error: fetchError.message });
      ResponseWriter.sendError(res, fetchError.message, 502);
      return;
    }

    let metadata = null;
    let content = fetched.content;
    const isHtml = fetched.contentType.includes('text/html');
    const isText = fetched.contentType.includes('text/') || fetched.contentType.includes('xml') || fetched.contentType.includes('json');

    if (isHtml) {
      metadata = ContentProcessor.extractMetadata(content, fetched.url);
      content = ContentProcessor.sanitizeHTML(content);
    } else if (!isText) {
      // Binary content isn't useful to render as text; keep the response small.
      content = `[Binary content: ${fetched.contentType || 'unknown type'}]`;
    }

    const responseData = {
      url: fetched.url,
      contentType: fetched.contentType,
      charset: fetched.charset,
      status: fetched.status,
      size: content.length,
      content,
      metadata,
      cached: false,
      timestamp: new Date().toISOString(),
    };

    cache.set(cacheKey, responseData);
    ResponseWriter.sendSuccess(res, responseData);
    Logger.info('Proxy success', { url: targetURL, size: content.length, contentType: fetched.contentType, charset: fetched.charset });
  } catch (error) {
    Logger.error('Proxy error', { error: error.message });
    ResponseWriter.sendError(res, error.message, 500);
  }
}

module.exports = handler;
