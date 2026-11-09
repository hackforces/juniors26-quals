'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

// Дефолт — /tmp: платформа (Jury) передаёт только CTF_FLAG/FLAG, без compose-env,
// а /tmp записываем во всех профилях рантайма (k8s emptyDir, docker tmpfs).
// path.join(__dirname, '..', 'data') тут нельзя: в контейнере приложение лежит
// плоско в /app, и '..' даёт '/data' (EACCES у непривилегированного пользователя).
const DB_PATH = process.env.DB_PATH || '/tmp/club.db';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  login         TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  balance       INTEGER NOT NULL DEFAULT 0,
  is_vip        INTEGER NOT NULL DEFAULT 0,
  avatar        TEXT NOT NULL DEFAULT '🙂',
  bio           TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bonus_claims (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  amount     INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  code        TEXT NOT NULL UNIQUE,
  title       TEXT NOT NULL,
  price       INTEGER NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  hidden      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  item_id    INTEGER NOT NULL REFERENCES items(id),
  quantity   INTEGER NOT NULL DEFAULT 1,
  note       TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tickets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  subject    TEXT NOT NULL,
  message    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'in_progress',
  reply      TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_bonus_claims_user ON bonus_claims(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_user ON tickets(user_id);
`);

module.exports = { db, DB_PATH };
