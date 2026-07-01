/**
 * ════════════════════════════════════════════════════════════════
 * MChat Proxy — fetches a page server-side, strips scripts/styles,
 * returns sanitizable HTML + metadata so the browser panel can render
 * it as plain DOM instead of an <iframe>. This is what avoids CSP /
 * X-Frame-Options blocking entirely: the target site's CSP headers
 * only govern requests made *by a browser rendering that page*, and
 * here the page is never rendered as a page — it's fetched as data.
 *
 * Response shape (consumed by index.html's loadBrowserPage()):
 *   { error, url, contentType, status, size, content, metadata, cached }
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
// CONTENT FETCHING
// ═══════════════════════════════════════════════════════════

class ContentProcessor {
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
          'Accept-Language': 'en-US,en;q=0.9',
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

      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > CONFIG.MAX_CONTENT_SIZE) {
        throw new Error(`Content too large: ${buffer.byteLength} bytes`);
      }

      return {
        content: Buffer.from(buffer).toString('utf-8'),
        contentType: response.headers.get('content-type') || '',
        status: response.status,
        url: response.url,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') throw new Error('Request timed out');
      throw error;
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

  static sanitizeHTML(html) {
    let out = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    out = out.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
    out = out.replace(/\son\w+\s*=\s*"[^"]*"/gi, '');
    out = out.replace(/\son\w+\s*=\s*'[^']*'/gi, '');
    out = out.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    if (out.length > 150000) out = out.slice(0, 150000) + '\n<!-- content truncated -->';
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

    const fetched = await ContentProcessor.fetchContent(targetURL);

    let metadata = null;
    let content = fetched.content;
    if (fetched.contentType.includes('text/html')) {
      metadata = ContentProcessor.extractMetadata(content, fetched.url);
      content = ContentProcessor.sanitizeHTML(content);
    } else if (!fetched.contentType.includes('text/')) {
      // Binary content isn't useful to render as text; keep the response small.
      content = `[Binary content: ${fetched.contentType || 'unknown type'}]`;
    }

    const responseData = {
      url: fetched.url,
      contentType: fetched.contentType,
      status: fetched.status,
      size: content.length,
      content,
      metadata,
      cached: false,
      timestamp: new Date().toISOString(),
    };

    cache.set(cacheKey, responseData);
    ResponseWriter.sendSuccess(res, responseData);
    Logger.info('Proxy success', { url: targetURL, size: content.length, contentType: fetched.contentType });
  } catch (error) {
    Logger.error('Proxy error', { error: error.message });
    ResponseWriter.sendError(res, error.message, 500);
  }
}

module.exports = handler;
