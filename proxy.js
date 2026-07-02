/* CARTINT CORS Proxy + Dark Web Scraper
   Run: node proxy.js
   Proxies requests, serves static files, and provides dark web search
   including Ahmia (.onion index), paste site monitoring, and optional
   Tor-backed .onion scraping.

   Optional Tor support: npm install socks-proxy-agent
   Then start Tor: tor or service tor start */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = 3001;
const STATIC_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const ALLOWED_DOMAINS = [
  'api.ransomware.live',
  'api-pro.ransomware.live',
  'www.circl.lu',
  'www.botvrij.eu',
  'ahmia.fi',
  'www.ahmia.fi',
  'psbdmp.ws',
  'www.psbdmp.ws',
  'darknetlive.com',
  'www.darknetlive.com',
  'raw.githubusercontent.com',
  'asrg.io',
  'www.asrg.io'
];

// API keys for authenticated endpoints (injected as X-API-KEY header)
const API_KEYS = {
  'api-pro.ransomware.live': '2e293cb7-6fc9-463f-92fd-6c2de399046e'
};

// ---- Optional Tor Support ----
// If socks-proxy-agent is installed and Tor is running, .onion scraping works.
let SocksProxyAgent = null;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
  console.log('[CARTINT] Tor support enabled (socks-proxy-agent detected)');
} catch (e) {
  console.log('[CARTINT] Tor support disabled — install socks-proxy-agent for .onion scraping');
}

const TOR_PROXY = 'socks5h://127.0.0.1:9050';
let torAgent = null;

function getTorAgent() {
  if (!SocksProxyAgent) return null;
  if (!torAgent) {
    try {
      torAgent = new SocksProxyAgent(TOR_PROXY);
    } catch (e) {
      return null;
    }
  }
  return torAgent;
}

// ---- Helpers ----

function sendJSON(res, code, data) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(body);
}

function fetchHTTPS(url, options = {}) {
  return new Promise((resolve, reject) => {
    const reqOptions = {
      headers: options.headers || { 'User-Agent': 'CARTINT-Dashboard/3.0', 'Accept': 'application/json' },
      timeout: options.timeout || 60000
    };

    // Use Tor agent for .onion URLs
    const targetHost = (() => { try { return new URL(url).hostname; } catch { return ''; } })();
    if (targetHost.endsWith('.onion') && SocksProxyAgent) {
      reqOptions.agent = getTorAgent();
      reqOptions.timeout = 90000; // Tor is slow
    }

    const req = https.get(url, reqOptions, (resp) => {
      // Follow one redirect
      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.headers.location) {
        https.get(resp.headers.location, reqOptions, resolve).on('error', reject);
        return;
      }
      resolve(resp);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

function fetchBody(resp, maxBytes = 2000000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    resp.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) { resp.destroy(); reject(new Error('Response too large')); return; }
      chunks.push(chunk);
    });
    resp.on('end', () => {
      const buf = Buffer.concat(chunks);
      resolve(buf.toString(resp.encoding || 'utf-8'));
    });
    resp.on('error', reject);
  });
}

// ---- Ahmia Search Parser ----
// Parses Ahmia.fi search results HTML and extracts .onion links with context

function parseAhmiaHTML(html) {
  const results = [];
  const seen = new Set();

  // Ahmia results contain .onion links — extract them with surrounding text
  const onionRegex = /https?:\/\/([a-z0-9]{16,56}\.onion)[^\s"'<>\)]*/gi;
  let match;

  while ((match = onionRegex.exec(html)) !== null) {
    const url = match[0].replace(/[.,;!?]$/, '');
    const onion = match[1];
    if (seen.has(onion)) continue;
    seen.add(onion);

    // Extract surrounding text as context (300 chars each direction)
    const start = Math.max(0, match.index - 300);
    const end = Math.min(html.length, match.index + url.length + 300);
    const rawContext = html.substring(start, end);

    // Strip HTML tags and normalize whitespace
    const context = rawContext
      .replace(/<[^>]+>/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/\s+/g, ' ')
      .trim();

    // Try to extract a meaningful title
    // Look for the first text segment before the URL
    const beforeText = context.substring(0, Math.max(0, match.index - start)).trim();
    const afterText = context.substring(match.index - start + url.length).trim();

    let title = '';
    if (beforeText.length > 5) {
      // Use text before the URL as title
      title = beforeText.substring(0, 120);
    } else if (afterText.length > 5) {
      title = afterText.substring(0, 120);
    } else {
      title = onion;
    }

    results.push({
      url,
      title: title.trim(),
      description: context.substring(0, 400)
    });
  }

  return results;
}

// ---- Dark Web Search Engine Scraper (Tor-backed) ----
// Searches multiple dark web search engines via Tor, like Robin
// Only works when socks-proxy-agent is installed and Tor is running.

const DARKWEB_SEARCH_ENGINES = [
  { name: 'Ahmia', url: 'https://ahmia.fi/search/?q={query}', parse: parseAhmiaHTML },
  { name: 'Tor66', url: 'http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}', parse: parseAhmiaHTML },
  { name: 'OnionLand', url: 'http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}', parse: parseAhmiaHTML },
];

async function searchDarkWebEngines(query) {
  if (!SocksProxyAgent) {
    // Fallback: only use Ahmia clearweb
    try {
      const resp = await fetchHTTPS(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`, { timeout: 30000 });
      const html = await fetchBody(resp);
      return parseAhmiaHTML(html);
    } catch (e) {
      console.warn(`[CARTINT] Ahmia clearweb search failed: ${e.message}`);
      return [];
    }
  }

  const allResults = [];
  for (const engine of DARKWEB_SEARCH_ENGINES) {
    try {
      const url = engine.url.replace('{query}', encodeURIComponent(query));
      const resp = await fetchHTTPS(url, { timeout: 45000 });
      if (resp.statusCode === 200) {
        const html = await fetchBody(resp);
        const results = engine.parse(html);
        allResults.push(...results.map(r => ({ ...r, _engine: engine.name })));
        console.log(`[CARTINT] ${engine.name}: ${results.length} results for "${query}"`);
      }
    } catch (e) {
      console.warn(`[CARTINT] ${engine.name} search failed: ${e.message}`);
    }
  }
  return allResults;
}

// ---- .onion Page Scraper ----

async function scrapeOnionPage(url) {
  if (!SocksProxyAgent) {
    return { error: 'Tor not available — install socks-proxy-agent and start Tor' };
  }

  try {
    const resp = await fetchHTTPS(url, { timeout: 60000 });
    if (resp.statusCode !== 200) {
      return { error: `HTTP ${resp.statusCode}` };
    }

    const html = await fetchBody(resp, 1000000);

    // Extract text content (strip scripts, styles, tags)
    const text = html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/\s+/g, ' ')
      .trim();

    // Extract title
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : url;

    return {
      url,
      title,
      text: text.substring(0, 5000),
      length: text.length
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ---- Server ----

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const reqUrl = new URL(req.url, `http://localhost:${PORT}`);

  // ---- API Endpoints ----

  // /api/ahmia-search?q=...
  if (reqUrl.pathname === '/api/ahmia-search') {
    const query = reqUrl.searchParams.get('q');
    if (!query) { sendJSON(res, 400, { error: 'Missing ?q= parameter' }); return; }

    (async () => {
      try {
        const results = await searchDarkWebEngines(query);
        sendJSON(res, 200, { query, count: results.length, results });
      } catch (e) {
        sendJSON(res, 502, { error: e.message });
      }
    })();
    return;
  }

  // /api/paste-search?q=...
  if (reqUrl.pathname === '/api/paste-search') {
    const query = reqUrl.searchParams.get('q');
    if (!query) { sendJSON(res, 400, { error: 'Missing ?q= parameter' }); return; }

    (async () => {
      try {
        const url = `https://psbdmp.ws/api/search/${encodeURIComponent(query)}`;
        const resp = await fetchHTTPS(url, { timeout: 15000 });
        const body = await fetchBody(resp, 500000);
        let data;
        try { data = JSON.parse(body); }
        catch { data = []; }
        sendJSON(res, 200, { query, count: Array.isArray(data) ? data.length : 0, results: data });
      } catch (e) {
        sendJSON(res, 502, { error: e.message });
      }
    })();
    return;
  }

  // /api/darkweb-scrape?url=...
  if (reqUrl.pathname === '/api/darkweb-scrape') {
    const targetUrl = reqUrl.searchParams.get('url');
    if (!targetUrl) { sendJSON(res, 400, { error: 'Missing ?url= parameter' }); return; }

    let targetHost;
    try { targetHost = new URL(targetUrl).hostname; }
    catch { sendJSON(res, 400, { error: 'Invalid URL' }); return; }

    if (!targetHost.endsWith('.onion') && !ALLOWED_DOMAINS.includes(targetHost)) {
      sendJSON(res, 403, { error: `Domain ${targetHost} is not allowed` });
      return;
    }

    (async () => {
      const result = await scrapeOnionPage(targetUrl);
      sendJSON(res, 200, result);
    })();
    return;
  }

  // /api/tor-status — check if Tor is available
  if (reqUrl.pathname === '/api/tor-status') {
    sendJSON(res, 200, {
      torAvailable: !!SocksProxyAgent,
      agent: SocksProxyAgent ? 'socks-proxy-agent' : null,
      proxy: SocksProxyAgent ? TOR_PROXY : null
    });
    return;
  }

  // ---- Static File Serving ----
  if (!reqUrl.pathname.startsWith('/proxy') && !reqUrl.pathname.startsWith('/api/')) {
    let filePath = reqUrl.pathname === '/' ? '/index.html' : reqUrl.pathname;
    filePath = path.join(STATIC_DIR, filePath);
    // Prevent directory traversal
    if (!filePath.startsWith(STATIC_DIR)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      res.writeHead(200, { 'Content-Type': mime });
      res.end(data);
    });
    return;
  }

  // ---- Generic CORS Proxy ----
  const targetUrl = reqUrl.searchParams.get('url');

  if (!targetUrl) {
    sendJSON(res, 400, { error: 'Missing ?url= parameter' });
    return;
  }

  let targetHost;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    sendJSON(res, 400, { error: 'Invalid URL' });
    return;
  }

  if (!ALLOWED_DOMAINS.includes(targetHost)) {
    sendJSON(res, 403, { error: `Domain ${targetHost} is not allowed` });
    return;
  }

  let responded = false;

  function sendError(code, message) {
    if (responded) return;
    responded = true;
    sendJSON(res, code, { error: message });
  }

  function pipeResponse(proxyRes) {
    if (responded) return;
    responded = true;
    res.writeHead(proxyRes.statusCode, {
      'Content-Type': proxyRes.headers['content-type'] || 'application/json'
    });
    proxyRes.pipe(res);
  }

  // Build headers, inject API key if available for this domain
  const reqHeaders = {
    'User-Agent': 'CARTINT-Dashboard/3.0',
    'Accept': 'application/json'
  };
  if (API_KEYS[targetHost]) {
    reqHeaders['X-API-KEY'] = API_KEYS[targetHost];
  }

  const proxyReq = https.get(targetUrl, {
    headers: reqHeaders,
    timeout: 60000
  }, (proxyRes) => {
    // Follow one redirect
    if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
      https.get(proxyRes.headers.location, {
        headers: { 'User-Agent': 'CARTINT-Dashboard/3.0', 'Accept': 'application/json' },
        timeout: 60000
      }, (redirectRes) => {
        pipeResponse(redirectRes);
      }).on('error', (e) => {
        sendError(502, `Redirect failed: ${e.message}`);
      });
      return;
    }
    pipeResponse(proxyRes);
  });

  proxyReq.on('error', (e) => sendError(502, `Proxy error: ${e.message}`));
  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    sendError(504, 'Upstream timeout');
  });
});

server.listen(PORT, () => {
  console.log(`[CARTINT] Server running on http://localhost:${PORT}`);
  console.log(`[CARTINT] Dashboard: http://localhost:${PORT}/`);
  console.log(`[CARTINT] ATM Matrix: http://localhost:${PORT}/matrix.html`);
  console.log(`[CARTINT] Proxy domains: ${ALLOWED_DOMAINS.join(', ')}`);
  console.log(`[CARTINT] API endpoints:`);
  console.log(`[CARTINT]   /api/ahmia-search?q=...  — Dark web search (Ahmia + Tor engines)`);
  console.log(`[CARTINT]   /api/paste-search?q=...  — Paste site search (psbdmp.ws)`);
  console.log(`[CARTINT]   /api/darkweb-scrape?url=... — .onion page scraper (requires Tor)`);
  console.log(`[CARTINT]   /api/tor-status           — Check Tor availability`);
  console.log(`[CARTINT] Tor: ${SocksProxyAgent ? 'ENABLED' : 'DISABLED (install socks-proxy-agent for .onion scraping)'}`);
});
