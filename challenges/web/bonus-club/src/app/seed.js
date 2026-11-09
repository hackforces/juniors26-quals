'use strict';

const crypto = require('crypto');
const { db } = require('./db');

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 32).toString('hex');
}

const ITEMS = [
  {
    code: 'postcard',
    title: 'Открытка клуба',
    price: 40,
    description: 'Печатная открытка с видом клуба.'
  },
  {
    code: 'keychain',
    title: 'Брелок «Bonus»',
    price: 60,
    description: 'Акриловый брелок участника клуба.'
  },
  {
    code: 'stickers',
    title: 'Наклейки',
    price: 80,
    description: 'Комплект фирменных наклеек.'
  },
  {
    code: 'mug',
    title: 'Кружка «Bonus Club»',
    price: 250,
    description: 'Керамическая кружка участника клуба.'
  },
  {
    code: 'tshirt',
    title: 'Футболка клуба',
    price: 350,
    description: 'Хлопковая футболка с логотипом.'
  },
  {
    code: 'vip',
    title: 'VIP-статус клуба',
    price: 400,
    description: 'Приоритетная поддержка, клубная переписка и привилегии участника.'
  },
  {
    code: 'flag_plush',
    title: 'Плед «Флаг»',
    price: 100000,
    description: 'Плед с принтом флага клуба. Тот самый флаг. Правда-правда.'
  },
  {
    code: 'staff_reward',
    title: 'Служебная награда',
    price: 0,
    description: 'Internal: ежегодная награда для сотрудников клуба.',
    hidden: true
  }
];

const STAFF_ORDER_ID = 228;

function main() {
  const flag = process.env.CTF_FLAG;
  if (!flag) {
    throw new Error('CTF_FLAG env must be set');
  }

  const seedAll = db.transaction(() => {
    const insertItem = db.prepare(
      `INSERT INTO items (code, title, price, description, hidden)
       VALUES (@code, @title, @price, @description, @hidden)
       ON CONFLICT (code) DO NOTHING`
    );
    for (const it of ITEMS) {
      insertItem.run({
        code: it.code,
        title: it.title,
        price: it.price,
        description: it.description,
        hidden: it.hidden ? 1 : 0
      });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(
      crypto.randomBytes(24).toString('hex') + crypto.randomBytes(24).toString('hex'),
      salt
    );
    db.prepare(
      `INSERT INTO users (login, password_salt, password_hash, is_vip)
       VALUES ('staff', ?, ?, 1)
       ON CONFLICT (login) DO NOTHING`
    ).run(salt, hash);

    const staffId = db.prepare(`SELECT id FROM users WHERE login = 'staff'`).get().id;
    const rewardId = db.prepare(`SELECT id FROM items WHERE code = 'staff_reward'`).get().id;

    const existing = db
      .prepare(`SELECT id FROM orders WHERE user_id = ? AND item_id = ? LIMIT 1`)
      .get(staffId, rewardId);
    if (existing) {
      db.prepare(`UPDATE orders SET note = ? WHERE id = ?`).run(flag, existing.id);
    } else {
      db.prepare(
        `INSERT INTO orders (id, user_id, item_id, note) VALUES (?, ?, ?, ?)`
      ).run(STAFF_ORDER_ID, staffId, rewardId, flag);
    }
  });

  seedAll();
  console.log('[seed] done');
}

try {
  main();
} catch (e) {
  console.error('[seed] failed:', e);
  process.exit(1);
}
