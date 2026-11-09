'use strict';

const express = require('express');

const router = express.Router();

router.get('/check', async (req, res) => {
  const uid = parseInt(req.query.uid || '0', 10) || 0;
  if (uid <= 0) {
    return res.status(400).json({ ok: false, error: 'uid required' });
  }
  await new Promise((resolve) => setTimeout(resolve, 100 + Math.random() * 50));
  const score = ((uid * 2654435761) % 1000) / 1000;
  res.json({ ok: true, score });
});

async function check(uid) {
  const base = `http://127.0.0.1:${process.env.PORT || 8080}`;
  const r = await fetch(`${base}/internal/antifraud/check?uid=${encodeURIComponent(uid)}`, {
    headers: { 'X-Internal-Call': '1' }
  });
  if (!r.ok) {
    throw new Error(`antifraud failed: HTTP ${r.status}`);
  }
  const data = await r.json();
  if (!data.ok) {
    throw new Error('antifraud rejected');
  }
  return data;
}

module.exports = { router, check };
