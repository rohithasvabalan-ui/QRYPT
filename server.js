/**
 * QRYPT – QR Code Protection
 * Developed by Team Cyber Titans
 *
 * Zero-Dependency Local Development Server (server.js)
 * Runs natively on Node.js without requiring npm install or external packages.
 *
 * Usage:
 *   node server.js
 * Opens at: http://localhost:5000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 5000;
const ROOT_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp'
};

const server = http.createServer((req, res) => {
  // Normalize URL
  let parsedUrl = req.url.split('?')[0];
  if (parsedUrl === '/') {
    parsedUrl = '/index.html';
  }

  const safePath = path.normalize(decodeURIComponent(parsedUrl)).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(ROOT_DIR, safePath);

  // Security check: ensure path stays within ROOT_DIR
  if (!filePath.startsWith(ROOT_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found: ' + safePath);
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache',
      'Access-Control-Allow-Origin': '*'
    });

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('='.repeat(65));
  console.log(' QRYPT – QR Code Protection');
  console.log(' Developed by Team Cyber Titans');
  console.log(` Server actively running at: http://127.0.0.1:${PORT}`);
  console.log(' Open this URL in your browser or run Live Server in VS Code.');
  console.log('='.repeat(65));
});
