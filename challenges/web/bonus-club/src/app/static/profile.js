'use strict';

const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const data = await r.json().catch(() => ({}));
  return { status: r.status, data };
}

function showMsg(el, text, ok) {
  el.textContent = text || '';
  el.className = 'msg ' + (ok ? 'ok' : text ? 'err' : '');
}

function fmtDate(iso) {
  try {
    return new Date(iso + 'Z').toLocaleDateString('ru-RU', {
      day: 'numeric',
      month: 'long',
      year: 'numeric'
    });
  } catch {
    return '';
  }
}

function renderAvatar(el, avatar) {
  el.textContent = '';
  if (avatar && avatar.startsWith('/avatars/')) {
    const img = document.createElement('img');
    img.src = avatar;
    img.alt = '';
    el.appendChild(img);
  } else {
    el.textContent = avatar || '🙂';
  }
}

async function load() {
  const { status, data } = await api('/api/me');
  if (status !== 200) {
    location.href = '/';
    return;
  }
  $('userbox').classList.remove('hidden');
  $('who').textContent = data.login;
  $('balance').textContent = data.balance + ' pt';
  $('vippill').classList.toggle('hidden', !data.is_vip);
  renderAvatar($('avatarBadge'), data.avatar);
  renderAvatar($('profileAvatar'), data.avatar);

  $('profileLogin').textContent = data.login;
  $('profileMeta').textContent =
    `В клубе с ${fmtDate(data.created_at)} · заказов: ${data.orders_count} · баланс: ${data.balance} pt` +
    (data.is_vip ? ' · VIP' : '');
  $('profileBio').textContent = data.bio;
  $('bio').value = data.bio;

  await loadOrders();
}

async function loadOrders() {
  const { data } = await api('/api/orders');
  const box = $('orders');
  box.innerHTML = '';
  if (!data.orders.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'Заказов пока нет.';
    box.appendChild(empty);
    return;
  }
  for (const o of data.orders) {
    const row = document.createElement('div');
    row.className = 'orderrow';
    const left = document.createElement('span');
    left.textContent =
      (o.quantity > 1 ? `#${o.id.slice(0, 8)} · ${o.title} ×${o.quantity}` : `#${o.id.slice(0, 8)} · ${o.title}`);
    const right = document.createElement('span');
    right.className = 'note';
    right.textContent = o.note;
    row.append(left, right);
    box.appendChild(row);
  }
}

$('avatarform').onsubmit = async (e) => {
  e.preventDefault();
  const file = $('avatarfile').files[0];
  if (!file) {
    showMsg($('avatarmsg'), 'Выберите файл картинки', false);
    return;
  }
  const fd = new FormData();
  fd.append('avatar', file);
  $('avatarupload').disabled = true;
  const r = await fetch('/api/profile/avatar', { method: 'POST', body: fd });
  const data = await r.json().catch(() => ({}));
  $('avatarupload').disabled = false;
  if (!r.ok) {
    showMsg($('avatarmsg'), data.error || 'Ошибка загрузки', false);
    return;
  }
  $('avatarfile').value = '';
  showMsg($('avatarmsg'), 'Аватарка обновлена', true);
  await load();
};

$('biosave').onclick = async () => {
  const bio = $('bio').value;
  if (bio.length > 500) {
    showMsg($('biomsg'), 'Описание: до 500 символов', false);
    return;
  }
  $('biosave').disabled = true;
  const { status, data } = await api('/api/profile/bio', { method: 'POST', body: { bio } });
  $('biosave').disabled = false;
  if (status !== 200) {
    showMsg($('biomsg'), data.error || 'Ошибка', false);
    return;
  }
  showMsg($('biomsg'), 'Описание сохранено', true);
  await load();
};

$('logout').onclick = async () => {
  await api('/api/logout', { method: 'POST' });
  location.href = '/';
};

load();
