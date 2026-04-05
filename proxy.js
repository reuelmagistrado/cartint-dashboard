/* CARTINT CORS Proxy — lightweight local proxy for APIs without CORS headers
   Run: node proxy.js
   Proxies requests from the dashboard to ransomware.live and other blocked APIs */

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
  'www.botvrij.eu'
];

// API keys for authenticated endpoints (injected as X-API-KEY header)
const API_KEYS = {
  'api-pro.ransomware.live': '2e293cb7-6fc9-463f-92fd-6c2de399046e'
};

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

  // Serve static files for non-proxy requests
  if (!reqUrl.pathname.startsWith('/proxy')) {
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

  const targetUrl = reqUrl.searchParams.get('url');

  if (!targetUrl) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Missing ?url= parameter' }));
    return;
  }

  let targetHost;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid URL' }));
    return;
  }

  if (!ALLOWED_DOMAINS.includes(targetHost)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Domain ${targetHost} is not allowed` }));
    return;
  }

  let responded = false;

  function sendError(code, message) {
    if (responded) return;
    responded = true;
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: message }));
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
    'User-Agent': 'CARTINT-Dashboard/2.0',
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
        headers: { 'User-Agent': 'CARTINT-Dashboard/2.0', 'Accept': 'application/json' },
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
});
