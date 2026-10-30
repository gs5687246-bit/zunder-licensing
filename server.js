'use strict';
// Zunder Licensing - painel de licencas do Zunder Optimizer
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const TAG = 'ZNDR1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'licenses.json');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'zunder';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(24).toString('hex');
const PRIVATE_KEY_B64 = process.env.LICENSE_PRIVATE_KEY || '';

if (!process.env.ADMIN_PASSWORD) console.warn('[warn] ADMIN_PASSWORD nao definida, usando "zunder"');
if (!PRIVATE_KEY_B64) {
  console.error('[fatal] LICENSE_PRIVATE_KEY nao definida');
  process.exit(1);
}

let privateKey;
try {
  privateKey = crypto.createPrivateKey({
    key: Buffer.from(PRIVATE_KEY_B64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
} catch (e) {
  console.error('[fatal] LICENSE_PRIVATE_KEY invalida: ' + e.message);
  process.exit(1);
}

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function makeKey(name, hwid, days) {
  const issued = Math.floor(Date.now() / 1000);
  const expiry = issued + days * 86400;
  const json = JSON.stringify({ n: name, h: hwid, e: expiry, i: issued });
  const payload = Buffer.from(json, 'utf8');
  const signature = crypto.sign('sha256', payload, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return TAG + '.' + b64url(payload) + '.' + b64url(signature);
}

// ---------- storage ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
let licenses = [];
try {
  licenses = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!Array.isArray(licenses)) licenses = [];
} catch { licenses = []; }

function save() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(licenses, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

// ---------- auth ----------
function authToken() {
  return crypto.createHmac('sha256', SESSION_SECRET).update('zunder-admin-v1').digest('hex');
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(pair => {
    const i = pair.indexOf('=');
    if (i < 0) return;
    out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  });
  return out;
}

function isAuthed(req) {
  return parseCookies(req).auth === authToken();
}

function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.status(401).json({ ok: false, error: 'Nao autenticado' });
  next();
}

// login attempt throttle
const attempts = new Map();
function tooMany(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  return Date.now() < a.until && a.count >= 8;
}
function failed(ip) {
  const a = attempts.get(ip) || { count: 0, until: 0 };
  a.count++;
  a.until = Date.now() + 5 * 60 * 1000;
  if (Date.now() > a.until - 5 * 60 * 1000 + 1000) a.count = 1;
  attempts.set(ip, a);
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

app.get('/health', (req, res) => res.json({ ok: true, service: 'zunder-licensing' }));

app.post('/api/login', (req, res) => {
  const ip = req.ip || 'x';
  if (tooMany(ip)) return res.status(429).json({ ok: false, error: 'Muitas tentativas. Aguarde 5 min.' });
  const p = String((req.body && req.body.password) || '');
  const a = Buffer.from(p);
  const b = Buffer.from(ADMIN_PASSWORD);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) {
    failed(ip);
    return res.status(401).json({ ok: false, error: 'Senha incorreta' });
  }
  res.setHeader('Set-Cookie',
    'auth=' + authToken() + '; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800' +
    (process.env.NODE_ENV === 'production' ? '; Secure' : ''));
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'auth=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ ok: true }));

app.get('/api/licenses', requireAuth, (req, res) => {
  res.json({ ok: true, licenses: licenses.slice().reverse() });
});

app.post('/api/licenses', requireAuth, (req, res) => {
  const body = req.body || {};
  const name = String(body.name || '').trim();
  const days = parseInt(body.days, 10);
  const any = body.any === true;
  let hwid = String(body.hwid || '').trim().toUpperCase();

  if (!name) return res.status(400).json({ ok: false, error: 'Nome obrigatorio' });
  if (!Number.isFinite(days) || days < 1 || days > 3650)
    return res.status(400).json({ ok: false, error: 'Dias invalidos (1 a 3650)' });
  if (any) hwid = '*';
  if (!any && !/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/.test(hwid))
    return res.status(400).json({ ok: false, error: 'HWID invalido (formato AABB-CCDD-EEFF)' });

  const now = Math.floor(Date.now() / 1000);
  const rec = {
    id: crypto.randomUUID(),
    name,
    hwid,
    days,
    created: now,
    expiry: now + days * 86400,
    key: makeKey(name, hwid, days),
    revoked: false,
  };
  licenses.push(rec);
  save();
  res.json({ ok: true, license: rec });
});

app.post('/api/licenses/:id/revoke', requireAuth, (req, res) => {
  const rec = licenses.find(l => l.id === req.params.id);
  if (!rec) return res.status(404).json({ ok: false, error: 'Licenca nao encontrada' });
  rec.revoked = !!(req.body && req.body.revoked);
  save();
  res.json({ ok: true, license: rec });
});

// verificacao publica usada pelo launcher
app.get('/api/verify', (req, res) => {
  const key = String(req.query.key || '').trim();
  if (!key) return res.json({ ok: false, reason: 'sem chave' });
  const rec = licenses.find(l => l.key === key);
  if (!rec) return res.json({ ok: false, reason: 'nao encontrada' });
  if (rec.revoked) return res.json({ ok: false, reason: 'revogada' });
  if (rec.expiry * 1000 < Date.now()) return res.json({ ok: false, reason: 'expirada' });
  res.json({ ok: true, name: rec.name, expiry: rec.expiry });
});

app.listen(PORT, () => {
  console.log('Zunder Licensing rodando na porta ' + PORT);
});
