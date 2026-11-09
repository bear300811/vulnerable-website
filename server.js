// Intentionally vulnerable web app for testing vulnerability-discovery pipelines.
// DO NOT deploy. Binds to 127.0.0.1 only. Run: node server.js  -> http://127.0.0.1:8000
// Node.js built-ins only (no npm install). Requires Node 22.13+ (node:sqlite).
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const FILES_DIR = path.join(ROOT, 'files');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const SECRET_KEY = 'sup3r-s3cret-k3y';
fs.mkdirSync(FILES_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT,
                     email TEXT, balance INTEGER, secret TEXT);
  CREATE TABLE comments(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
`);
const seed = db.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?)');
seed.run(1, 'admin', md5('admin123'), 'admin', 'admin@hearthfile.example', 99999, "admin's private note");
seed.run(2, 'alice', md5('alice2024'), 'user', 'alice@hearthfile.example', 1500, "alice's private note");
seed.run(3, 'bob', md5('password'), 'user', 'bob@hearthfile.example', 320, "bob's private note");

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'application/javascript',
  '.mjs': 'application/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.woff2': 'font/woff2', '.txt': 'text/plain' };

// ---- helpers ----------------------------------------------------------
function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  const ctype = headers['Content-Type'] || (typeof body === 'string' || Buffer.isBuffer(body)
    ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8');
  res.writeHead(status, { 'Content-Type': ctype, 'Content-Length': Buffer.byteLength(data), ...headers });
  res.end(data);
}
function json(res, status, obj, headers) { send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', ...headers }); }
function redirect(res, loc) { res.writeHead(302, { Location: loc }); res.end(); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readForm(req) {
  const raw = (await readBody(req)).toString('utf8');
  const ctype = req.headers['content-type'] || '';
  if (ctype.includes('application/json')) return JSON.parse(raw || '{}');
  return Object.fromEntries(new URLSearchParams(raw));
}
function getSession(req) {
  const m = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  try { return JSON.parse(Buffer.from(m[1], 'base64').toString('utf8')); } catch { return null; } // unsigned: client can edit it
}

// ---- API handlers -----------------------------------------------------
const api = {};

// SQL injection in login; weak MD5 password storage
api['POST /api/login'] = async (req, res) => {
  const f = await readForm(req);
  const sql = `SELECT id,username,role FROM users WHERE username='${f.username || ''}' AND password='${md5(f.password || '')}'`;
  const row = db.prepare(sql).get();
  if (!row) return json(res, 401, { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  const tok = Buffer.from(JSON.stringify({ id: row.id, username: row.username, role: row.role })).toString('base64');
  return json(res, 200, { ok: true, username: row.username }, { 'Set-Cookie': `session=${tok}; Path=/` });
};

// Mass assignment: the client chooses its own role on sign-up
api['POST /api/register'] = async (req, res) => {
  const f = await readForm(req);
  if (!f.username || !f.password) return json(res, 400, { error: '아이디와 비밀번호를 입력하세요.' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(f.username)) {
    return json(res, 409, { error: '이미 사용 중인 아이디입니다.' });
  }
  const role = f.role || 'user';
  const info = db.prepare('INSERT INTO users(username,password,role,email,balance,secret) VALUES(?,?,?,?,?,?)')
    .run(f.username, md5(f.password), role, `${f.username}@hearthfile.example`, 1000, `${f.username}의 비공개 메모`);
  return json(res, 201, { ok: true, id: Number(info.lastInsertRowid), username: f.username });
};

api['GET /api/search'] = (req, res, q) => {
  const rows = db.prepare('SELECT username FROM users WHERE username LIKE ?').all(`%${q.get('q') || ''}%`);
  return json(res, 200, { results: rows.map((r) => r.username) });
};

api['GET /api/comments'] = (req, res) => {
  return json(res, 200, { comments: db.prepare('SELECT author, body FROM comments ORDER BY id').all() });
};
api['POST /api/comments'] = async (req, res) => {
  const f = await readForm(req);
  db.prepare('INSERT INTO comments(author, body) VALUES(?,?)').run(f.author || '', f.body || '');
  return json(res, 201, { ok: true });
};

// IDOR: no ownership check on the id
api['GET /api/profile'] = (req, res, q) => {
  const row = db.prepare('SELECT username,email,secret,balance FROM users WHERE id=?').get(q.get('id') || '1');
  if (!row) return json(res, 404, { error: '고객을 찾을 수 없습니다.' });
  return json(res, 200, row);
};

api['GET /api/account'] = (req, res) => {
  const s = getSession(req);
  if (!s) return json(res, 401, { error: '먼저 로그인하세요.' });
  const row = db.prepare('SELECT username,balance FROM users WHERE id=?').get(s.id);
  return json(res, 200, row);
};

// CSRF: cookie-only auth, no token; negative amounts accepted
api['POST /api/transfer'] = async (req, res) => {
  const s = getSession(req);
  if (!s) return json(res, 401, { error: '먼저 로그인하세요.' });
  const f = await readForm(req);
  const amt = parseInt(f.amount || '0', 10);
  const to = f.to || '';
  db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(amt, s.id);
  db.prepare('UPDATE users SET balance=balance+? WHERE username=?').run(amt, to);
  return json(res, 200, { ok: true, amount: amt, to });
};

// Broken access control: role taken from the client-editable cookie
api['GET /api/admin'] = (req, res) => {
  const s = getSession(req);
  if (!s || s.role !== 'admin') return json(res, 403, { error: '관리자만 접근할 수 있습니다.' });
  return json(res, 200, { users: db.prepare('SELECT id,username,password,role,email FROM users').all() });
};

// OS command injection
api['GET /api/ping'] = (req, res, q) => {
  const host = q.get('host') || '127.0.0.1';
  const flag = process.platform === 'win32' ? '-n' : '-c';
  // Windows ping prints in the console code page (cp949), elsewhere in UTF-8
  const decode = (buf) => new TextDecoder(process.platform === 'win32' ? 'euc-kr' : 'utf-8').decode(buf);
  let out;
  try { out = decode(execSync(`ping ${flag} 1 ${host}`, { timeout: 8000 })); }
  catch (e) { out = decode(Buffer.concat([e.stdout || Buffer.alloc(0), e.stderr || Buffer.alloc(0)])) || String(e.message); }
  return send(res, 200, out);
};

// Path traversal on the file name
api['GET /api/file'] = (req, res, q) => {
  const data = fs.readFileSync(path.join(FILES_DIR, q.get('name') || ''));
  return send(res, 200, data, { 'Content-Type': 'text/plain; charset=utf-8' });
};

// SSRF: server fetches any URL the client gives
api['GET /api/fetch'] = async (req, res, q) => {
  const r = await fetch(q.get('url') || '', { signal: AbortSignal.timeout(3000) });
  const text = (await r.text()).slice(0, 4000);
  return send(res, 200, text);
};

// Unrestricted upload: no name, type or size checks; path traversal on write
api['POST /api/upload'] = async (req, res, q) => {
  const name = q.get('name') || 'upload.bin';
  const data = await readBody(req);
  const target = path.join(UPLOAD_DIR, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, data);
  return json(res, 201, { saved: `/uploads/${name}` });
};

// Sensitive data exposure
api['GET /api/debug'] = (req, res) => {
  return json(res, 200, {
    secret_key: SECRET_KEY, base_dir: ROOT, node: process.version,
    users: db.prepare('SELECT username,password,secret FROM users').all(),
  });
};

// Open redirect
const pageRoutes = {
  'GET /redirect': (req, res, q) => redirect(res, q.get('next') || '/'),
  'GET /robots.txt': (req, res) => send(res, 200,
    'User-agent: *\nDisallow: /admin.html\nDisallow: /api/debug\nDisallow: /files/\nDisallow: /uploads/\n',
    { 'Content-Type': 'text/plain; charset=utf-8' }),
};

// ---- server -----------------------------------------------------------
function serveStatic(req, res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\//, '');
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep) && file !== PUBLIC) return send(res, 403, 'Forbidden');
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, notFoundPage(), { 'Content-Type': MIME['.html'] });
  const ext = path.extname(file).toLowerCase();
  return send(res, 200, fs.readFileSync(file), { 'Content-Type': MIME[ext] || 'application/octet-stream' });
}
function notFoundPage() {
  return '<!doctype html><html lang="ko"><meta charset="utf-8"><title>페이지를 찾을 수 없음</title><link rel="stylesheet" href="/assets/system.css"><main class="wrap" style="padding:96px 0"><h1>페이지를 찾을 수 없습니다</h1><p><a href="/">홈으로 돌아가기</a></p></main>';
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://127.0.0.1');
    const key = `${req.method} ${u.pathname}`;
    if (req.method === 'GET' && u.pathname.startsWith('/uploads/')) {
      const target = path.join(UPLOAD_DIR, decodeURIComponent(u.pathname.slice('/uploads/'.length)));
      const data = fs.readFileSync(target);
      return send(res, 200, data, { 'Content-Type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream' });
    }
    if (pageRoutes[key]) return pageRoutes[key](req, res, u.searchParams);
    if (api[key]) return api[key](req, res, u.searchParams);
    if (req.method === 'GET' && !u.pathname.startsWith('/api/')) return serveStatic(req, res, u.pathname);
    return json(res, 404, { error: '찾을 수 없습니다' });
  } catch (e) {
    // verbose error disclosure
    json(res, 500, { error: String(e.message), stack: e.stack });
  }
});

// Local default is 127.0.0.1:8000. Docker sets HOST=0.0.0.0 so the published port is reachable.
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8000);
server.listen(PORT, HOST, () => console.log(`http://${HOST}:${PORT}`));
