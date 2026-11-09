// Shared helpers: token storage, authenticated fetch, small UI utilities.
const TOKEN_KEY = 'innoctf_token';

function getToken() { return localStorage.getItem(TOKEN_KEY); }
function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }

async function api(path, method = 'GET', body = null) {
  const headers = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;

  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });

  let data = null;
  try { data = await res.json(); } catch (_) { /* no body */ }

  if (!res.ok) {
    if (res.status === 401) { clearToken(); }
    const detail = data && data.detail ? data.detail : `Ошибка ${res.status}`;
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  return data;
}

function showMsg(id, text, kind = 'info') {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="alert alert-${kind}">${escapeHtml(text)}</div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Reflect auth state in the navbar and wire up logout.
async function renderAuthNav() {
  const inEls = document.querySelectorAll('[data-auth="in"]');
  const outEls = document.querySelectorAll('[data-auth="out"]');
  const show = (els, on) => els.forEach(e => e.style.display = on ? '' : 'none');

  if (!getToken()) { show(inEls, false); show(outEls, true); return; }
  try {
    const me = await api('/api/me', 'GET');
    const nu = document.getElementById('nav-user');
    if (nu) nu.textContent = `${me.username} · ⭐${me.total_score} · 💰${me.balance}`;
    show(inEls, true); show(outEls, false);
  } catch (_) {
    clearToken(); show(inEls, false); show(outEls, true);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  renderAuthNav();
  const logout = document.getElementById('logout');
  if (logout) logout.addEventListener('click', (e) => {
    e.preventDefault(); clearToken(); location.href = '/';
  });
});
