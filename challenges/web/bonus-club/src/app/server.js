'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const { db, DB_PATH } = require('./db');
const session = require('./lib/session');
const antifraud = require('./lib/antifraud');

const DATA_DIR = path.dirname(DB_PATH);
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const BONUS_AMOUNT = 100;
const MAX_QUANTITY = 10;
const MAX_AVATAR_BYTES = 512 * 1024;
const MAX_BIO_LENGTH = 500;
const OID_RE = /^[0-9a-f]{40}$/;
const TICKET_AUTO_REPLY =
  'Добрый день! Это автоматический ответ клубной поддержки. Мы получили ваше письмо и уже разбираемся. Ответ специалиста придёт в течение 48 часов.';

const IMG_FORMATS = [
  {
    ext: 'png',
    match: (b) =>
      b.length > 8 &&
      b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
      b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a
  },
  {
    ext: 'jpg',
    match: (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff
  },
  {
    ext: 'gif',
    match: (b) => b.length > 6 && b.subarray(0, 3).toString('latin1') === 'GIF'
  },
  {
    ext: 'webp',
    match: (b) =>
      b.length > 12 &&
      b.subarray(0, 4).toString('latin1') === 'RIFF' &&
      b.subarray(8, 12).toString('latin1') === 'WEBP'
  }
];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_AVATAR_BYTES, files: 1 }
});

const q = {
  me: db.prepare(
    `SELECT u.login, u.balance, u.is_vip, u.avatar, u.bio, u.created_at,
            EXISTS (SELECT 1 FROM bonus_claims c WHERE c.user_id = u.id) AS bonus_claimed,
            (SELECT count(*) FROM orders o WHERE o.user_id = u.id) AS orders_count
       FROM users u
      WHERE u.id = ?`
  ),
  insertUser: db.prepare(
    `INSERT INTO users (login, password_salt, password_hash, balance) VALUES (?, ?, ?, 0)`
  ),
  userByLogin: db.prepare(`SELECT id, password_salt, password_hash FROM users WHERE login = ?`),
  updateAvatar: db.prepare(`UPDATE users SET avatar = ? WHERE id = ?`),
  updateBio: db.prepare(`UPDATE users SET bio = ? WHERE id = ?`),
  bonusClaimed: db.prepare(`SELECT id FROM bonus_claims WHERE user_id = ? LIMIT 1`),
  balanceAdd: db.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`),
  bonusClaimInsert: db.prepare(`INSERT INTO bonus_claims (user_id, amount) VALUES (?, ?)`),
  balanceGet: db.prepare(`SELECT balance FROM users WHERE id = ?`),
  isVip: db.prepare(`SELECT is_vip FROM users WHERE id = ?`),
  itemByCode: db.prepare(`SELECT * FROM items WHERE code = ? AND hidden = 0`),
  buyItem: db.prepare(
    `UPDATE users
        SET balance = balance - ?,
            is_vip  = is_vip OR ?
      WHERE id = ? AND balance >= ?`
  ),
  insertOrder: db.prepare(
    `INSERT INTO orders (user_id, item_id, quantity, note) VALUES (?, ?, ?, ?)`
  ),
  myOrders: db.prepare(
    `SELECT o.id, i.title, i.code, o.quantity, o.note, o.created_at
       FROM orders o JOIN items i ON i.id = o.item_id
      WHERE o.user_id = ?
      ORDER BY o.id DESC`
  ),
  myOrder: db.prepare(
    `SELECT o.id, i.title, i.code, o.quantity, o.note, o.created_at, u.login AS owner
       FROM orders o
       JOIN items i ON i.id = o.item_id
       JOIN users u ON u.id = o.user_id
      WHERE o.id = ? AND o.user_id = ?`
  ),
  anyOrder: db.prepare(
    `SELECT o.id, i.title, i.code, o.quantity, o.note, o.created_at, u.login AS owner
       FROM orders o
       JOIN items i ON i.id = o.item_id
       JOIN users u ON u.id = o.user_id
      WHERE o.id = ?`
  ),
  allOrderIds: db.prepare(`SELECT id FROM orders`),
  insertTicket: db.prepare(
    `INSERT INTO tickets (user_id, subject, message, reply) VALUES (?, ?, ?, ?)`
  ),
  myTickets: db.prepare(
    `SELECT id, subject, message, status, reply, created_at
       FROM tickets
      WHERE user_id = ?
      ORDER BY id DESC
      LIMIT 50`
  )
};

const app = express();
app.use(express.json());

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 32).toString('hex');
}

function orderIdHash(id) {
  return crypto.createHash('sha1').update(String(id), 'utf8').digest('hex');
}

function findInternalOrderId(oid) {
  const row = q.allOrderIds.all().find((r) => orderIdHash(r.id) === oid);
  return row ? row.id : null;
}

function setSessionCookie(res, uid, login) {
  const token = session.sign({
    uid,
    login,
    exp: Math.floor(Date.now() / 1000) + session.TTL_SECONDS
  });
  res.setHeader('Set-Cookie', `${session.COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax`);
}

function requireAuth(req, res, next) {
  const payload = session.verify(parseCookies(req)[session.COOKIE]);
  if (!payload) {
    return res.status(401).json({ error: 'auth required' });
  }
  req.userId = payload.uid;
  req.login = payload.login;
  next();
}

function requireVip(req, res, next) {
  const row = q.isVip.get(req.userId);
  if (!row || !row.is_vip) {
    return res.status(403).json({ error: 'vip only' });
  }
  next();
}

app.use('/internal/antifraud', antifraud.router);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/register', (req, res) => {
  const { login, password } = req.body || {};
  if (
    !login || !password ||
    typeof login !== 'string' || typeof password !== 'string' ||
    !/^[a-zA-Z0-9_]{3,32}$/.test(login) ||
    password.length < 6
  ) {
    return res.status(400).json({ error: 'invalid login or password' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  let uid;
  try {
    const info = q.insertUser.run(login, salt, hash);
    uid = Number(info.lastInsertRowid);
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'login already taken' });
    }
    throw e;
  }
  setSessionCookie(res, uid, login);
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password) {
    return res.status(400).json({ error: 'login and password required' });
  }
  const user = q.userByLogin.get(String(login));
  if (!user || hashPassword(password, user.password_salt) !== user.password_hash) {
    return res.status(401).json({ error: 'bad credentials' });
  }
  setSessionCookie(res, user.id, login);
  res.json({ ok: true });
});

app.post('/api/logout', (_req, res) => {
  res.setHeader('Set-Cookie', `${session.COOKIE}=; Path=/; HttpOnly; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(q.me.get(req.userId));
});

app.post('/api/profile/bio', requireAuth, (req, res) => {
  const { bio } = req.body || {};
  if (typeof bio !== 'string' || bio.length > MAX_BIO_LENGTH) {
    return res.status(400).json({ error: 'invalid bio' });
  }
  q.updateBio.run(bio.trim(), req.userId);
  res.json({ ok: true });
});

app.post('/api/profile/avatar', requireAuth, upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'file required' });
  }
  const buf = req.file.buffer;
  const fmt = IMG_FORMATS.find((f) => f.match(buf));
  if (!fmt) {
    return res.status(400).json({ error: 'only png, jpg, gif or webp images are allowed' });
  }
  const name = `${crypto.randomBytes(16).toString('hex')}.${fmt.ext}`;
  fs.writeFileSync(path.join(UPLOADS_DIR, name), buf);

  const old = q.me.get(req.userId).avatar;
  if (old && old.startsWith('/avatars/')) {
    fs.unlink(path.join(UPLOADS_DIR, path.basename(old)), () => {});
  }

  const avatar = `/avatars/${name}`;
  q.updateAvatar.run(avatar, req.userId);
  res.json({ ok: true, avatar });
});

app.use('/avatars', express.static(UPLOADS_DIR, { maxAge: '1d' }));

app.post('/api/bonus', requireAuth, async (req, res) => {
  const uid = req.userId;

  const claimed = q.bonusClaimed.get(uid);
  if (claimed) {
    return res.status(409).json({ error: 'bonus already claimed' });
  }

  await antifraud.check(uid);

  q.balanceAdd.run(BONUS_AMOUNT, uid);
  q.bonusClaimInsert.run(uid, BONUS_AMOUNT);

  res.json({ ok: true, granted: BONUS_AMOUNT, balance: q.balanceGet.get(uid).balance });
});

app.get('/api/shop', (_req, res) => {
  const rows = db
    .prepare(`SELECT code, title, price, description FROM items WHERE hidden = 0 ORDER BY price`)
    .all();
  res.json({ items: rows });
});

app.post('/api/buy', requireAuth, (req, res) => {
  const { code, quantity } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'code required' });
  }
  const qty = quantity === undefined ? 1 : quantity;
  if (typeof qty !== 'number' || !Number.isInteger(qty) || qty < 1 || qty > MAX_QUANTITY) {
    return res.status(400).json({ error: `quantity must be an integer between 1 and ${MAX_QUANTITY}` });
  }
  const item = q.itemByCode.get(code);
  if (!item) {
    return res.status(404).json({ error: 'unknown item' });
  }
  if (item.code === 'vip' && qty !== 1) {
    return res.status(400).json({ error: 'vip status can be purchased once' });
  }

  const total = item.price * qty;
  const info = q.buyItem.run(total, item.code === 'vip' ? 1 : 0, req.userId, total);
  if (info.changes === 0) {
    return res.status(402).json({ error: 'insufficient funds' });
  }

  const note =
    item.code === 'flag_plush'
      ? 'Это просто плед с принтом. Настоящий флаг не продаётся.'
      : 'Заказ оформлен, ожидайте доставки.';
  q.insertOrder.run(req.userId, item.id, qty, note);

  res.json({
    ok: true,
    item: item.code,
    quantity: qty,
    balance: q.balanceGet.get(req.userId).balance,
    is_vip: q.isVip.get(req.userId).is_vip ? 1 : 0
  });
});

app.get('/api/orders', requireAuth, (req, res) => {
  const orders = q.myOrders.all(req.userId).map((o) => ({ ...o, id: orderIdHash(o.id) }));
  res.json({ orders });
});

app.get('/api/orders/:oid', requireAuth, (req, res) => {
  const oid = String(req.params.oid || '').toLowerCase();
  if (!OID_RE.test(oid)) {
    return res.status(400).json({ error: 'invalid order id' });
  }
  const internalId = findInternalOrderId(oid);
  if (!internalId) {
    return res.status(404).json({ error: 'order not found' });
  }
  const row = q.myOrder.get(internalId, req.userId);
  if (!row) {
    return res.status(403).json({ error: 'not your order' });
  }
  res.json({ ...row, id: oid });
});

const apiV1 = express.Router();
app.use('/api/v1', apiV1);

apiV1.get('/orders/:oid', requireAuth, requireVip, (req, res) => {
  const oid = String(req.params.oid || '').toLowerCase();
  if (!OID_RE.test(oid)) {
    return res.status(400).json({ error: 'invalid order id' });
  }
  const internalId = findInternalOrderId(oid);
  if (!internalId) {
    return res.status(404).json({ error: 'order not found' });
  }
  const row = q.anyOrder.get(internalId);
  if (!row) {
    return res.status(404).json({ error: 'order not found' });
  }
  res.json({ ...row, id: oid });
});

app.post('/api/support/tickets', requireAuth, requireVip, (req, res) => {
  const { subject, message } = req.body || {};
  if (
    typeof subject !== 'string' || typeof message !== 'string' ||
    subject.trim().length < 3 || subject.trim().length > 120 ||
    message.trim().length < 10 || message.trim().length > 2000
  ) {
    return res.status(400).json({ error: 'invalid subject or message' });
  }
  const info = q.insertTicket.run(req.userId, subject.trim(), message.trim(), TICKET_AUTO_REPLY);
  res.json({
    id: Number(info.lastInsertRowid),
    subject: subject.trim(),
    message: message.trim(),
    status: 'in_progress',
    reply: TICKET_AUTO_REPLY
  });
});

app.get('/api/support/tickets', requireAuth, requireVip, (req, res) => {
  res.json({ tickets: q.myTickets.all(req.userId) });
});

app.use(express.static(path.join(__dirname, 'static')));

app.use((_req, res) => {
  res.status(404).json({ error: 'not found' });
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'avatar must be an image up to 512 KB' });
  }
  console.error('[error]', err);
  res.status(500).json({ error: 'internal error' });
});

const PORT = Number(process.env.PORT || 8080);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[bonus-club] listening on :${PORT}`);
});
