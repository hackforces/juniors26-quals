'use strict';

const $ = (id) => document.getElementById(id);

const state = { authed: false, mode: 'login', busy: false, me: null };

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

function setMode(mode) {
  state.mode = mode;
  const isLogin = mode === 'login';
  $('tab-login').classList.toggle('active', isLogin);
  $('tab-reg').classList.toggle('active', !isLogin);
  $('authsubmit').textContent = isLogin ? 'Войти' : 'Создать аккаунт';
  showMsg($('authmsg'), '');
}

$('tab-login').onclick = () => setMode('login');
$('tab-reg').onclick = () => setMode('reg');

$('authform').onsubmit = async (e) => {
  e.preventDefault();
  if (state.busy) return;
  state.busy = true;
  $('authsubmit').disabled = true;

  const login = $('login').value.trim();
  const password = $('password').value;
  const endpoint = state.mode === 'login' ? '/api/login' : '/api/register';

  if (state.mode === 'reg') {
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(login)) {
      showMsg($('authmsg'), 'Логин: 3–32 символа, латиница, цифры и «_»', false);
      state.busy = false;
      $('authsubmit').disabled = false;
      return;
    }
    if (password.length < 6) {
      showMsg($('authmsg'), 'Пароль: минимум 6 символов', false);
      state.busy = false;
      $('authsubmit').disabled = false;
      return;
    }
  }

  const { status, data } = await api(endpoint, { method: 'POST', body: { login, password } });
  state.busy = false;
  $('authsubmit').disabled = false;

  if (status !== 200) {
    showMsg($('authmsg'), data.error || 'Ошибка запроса', false);
    return;
  }
  showMsg($('authmsg'), '');
  await enterClub();
};

$('logout').onclick = async () => {
  await api('/api/logout', { method: 'POST' });
  logoutUi();
};

$('avatarBadge').onclick = () => {
  if (state.authed) location.href = '/profile.html';
};

function logoutUi() {
  state.authed = false;
  state.me = null;
  $('auth').classList.remove('hidden');
  $('club').classList.add('hidden');
  $('userbox').classList.add('hidden');
  $('password').value = '';
  setMode('login');
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

async function enterClub() {
  const { status, data } = await api('/api/me');
  if (status !== 200) {
    logoutUi();
    return;
  }
  state.authed = true;
  state.me = data;
  $('auth').classList.add('hidden');
  $('club').classList.remove('hidden');
  $('userbox').classList.remove('hidden');

  $('who').textContent = data.login;
  $('balance').textContent = data.balance + ' pt';
  $('vippill').classList.toggle('hidden', !data.is_vip);
  renderAvatar($('avatarBadge'), data.avatar);

  $('bonuscard').classList.toggle('hidden', Boolean(data.bonus_claimed));
  $('vipzone').classList.toggle('hidden', !data.is_vip);

  await loadShop();
  await loadOrders();
  if (data.is_vip) {
    await loadTickets();
  }
}

async function loadShop() {
  const { data } = await api('/api/shop');
  const box = $('shop');
  box.innerHTML = '';
  for (const it of data.items) {
    const card = document.createElement('div');
    card.className = 'item';

    const title = document.createElement('div');
    title.className = 'title';
    title.textContent = it.title;

    const desc = document.createElement('p');
    desc.className = 'desc';
    desc.textContent = it.description;

    const price = document.createElement('div');
    price.className = 'price';
    price.textContent = it.price + ' pt';

    const qtyRow = document.createElement('div');
    qtyRow.className = 'qtyrow';

    const qtyLabel = document.createElement('label');
    qtyLabel.textContent = 'кол-во';

    const qtyInput = document.createElement('input');
    qtyInput.type = 'number';
    qtyInput.min = '1';
    qtyInput.max = '10';
    qtyInput.value = '1';

    qtyRow.append(qtyLabel, qtyInput);

    const btn = document.createElement('button');
    btn.className = 'btn primary';
    btn.type = 'button';
    btn.textContent = 'Купить';
    btn.onclick = () => buy(it.code, qtyInput, btn);

    card.append(title, desc, price, qtyRow, btn);
    box.appendChild(card);
  }
}

async function buy(code, qtyInput, btn) {
  const qty = Math.max(1, Math.min(10, Math.floor(Number(qtyInput.value) || 1)));
  qtyInput.value = String(qty);
  btn.disabled = true;
  const { status, data } = await api('/api/buy', { method: 'POST', body: { code, quantity: qty } });
  btn.disabled = false;
  if (status !== 200) {
    alert(data.error || 'Покупка не прошла');
    return;
  }
  await enterClub();
}

async function loadOrders() {
  const { data } = await api('/api/orders');
  const box = $('orders');
  box.innerHTML = '';
  if (!data.orders.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'Заказов пока нет — заберите бонус и загляните в магазин.';
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

$('ticketform').onsubmit = async (e) => {
  e.preventDefault();
  if (state.busy) return;
  const subject = $('tsubject').value.trim();
  const message = $('tmessage').value.trim();
  if (subject.length < 3 || subject.length > 120) {
    showMsg($('ticketmsg'), 'Тема: от 3 до 120 символов', false);
    return;
  }
  if (message.length < 10 || message.length > 2000) {
    showMsg($('ticketmsg'), 'Сообщение: от 10 до 2000 символов', false);
    return;
  }
  state.busy = true;
  $('ticketsubmit').disabled = true;
  const { status, data } = await api('/api/support/tickets', {
    method: 'POST',
    body: { subject, message }
  });
  state.busy = false;
  $('ticketsubmit').disabled = false;
  if (status !== 200) {
    showMsg($('ticketmsg'), data.error || 'Ошибка', false);
    return;
  }
  $('tsubject').value = '';
  $('tmessage').value = '';
  showMsg($('ticketmsg'), 'Письмо отправлено в поддержку', true);
  await loadTickets();
};

async function loadTickets() {
  const { status, data } = await api('/api/support/tickets');
  const box = $('tickets');
  box.innerHTML = '';
  if (status !== 200 || !data.tickets.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'Писем пока нет.';
    box.appendChild(empty);
    return;
  }
  for (const t of data.tickets) {
    const card = document.createElement('div');
    card.className = 'ticket';

    const subj = document.createElement('div');
    subj.className = 'subj';
    const subjText = document.createElement('span');
    subjText.textContent = t.subject;
    const st = document.createElement('span');
    st.className = 'status';
    st.textContent = 'в обработке';
    subj.append(subjText, st);

    const body = document.createElement('div');
    body.className = 'body';
    body.textContent = t.message;

    const reply = document.createElement('div');
    reply.className = 'reply';
    reply.textContent = 'Поддержка: ' + t.reply;

    card.append(subj, body, reply);
    box.appendChild(card);
  }
}

$('getbonus').onclick = async () => {
  const btn = $('getbonus');
  btn.disabled = true;
  btn.textContent = 'Зачисляем…';
  const { status, data } = await api('/api/bonus', { method: 'POST' });
  if (status !== 200) {
    btn.disabled = false;
    btn.textContent = 'Забрать бонус';
    showMsg($('bonusmsg'), data.error || 'Ошибка', false);
    if (status === 409) $('bonuscard').classList.add('hidden');
    return;
  }
  showMsg($('bonusmsg'), `Начислено +${data.granted} pt`, true);
  await enterClub();
};

(async () => {
  setMode('login');
  await enterClub();
})();
