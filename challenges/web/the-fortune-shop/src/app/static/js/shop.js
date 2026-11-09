// Shop page: list products, buy with earned points, show the purchase message.
const productsBox = document.getElementById('products');
const balanceEl = document.getElementById('balance');

function render(shop) {
  balanceEl.textContent = shop.balance;
  productsBox.innerHTML = '';
  for (const p of shop.products) {
    const canAfford = shop.balance >= p.price;
    const priceText = p.purchasable ? p.price : '∞';
    const col = document.createElement('div');
    col.className = 'col';
    let btn;
    if (!p.purchasable) {
      btn = '<button class="btn btn-outline-secondary w-100" disabled>Недоступно</button>';
    } else if (p.owned) {
      btn = '<button class="btn btn-outline-success w-100" disabled>Куплено</button>';
    } else {
      btn = `<button class="btn btn-primary w-100 buy" data-id="${p.id}" ${canAfford ? '' : 'disabled'}>
               Купить за ${p.price}
             </button>`;
    }
    col.innerHTML = `
      <div class="card bg-body-tertiary border-secondary-subtle h-100">
        <div class="card-body d-flex flex-column">
          <div class="fs-1">${p.emoji}</div>
          <h5 class="card-title">${escapeHtml(p.name)}</h5>
          <div class="text-secondary mb-3">Цена: ${priceText}</div>
          <div class="mt-auto">${btn}</div>
        </div>
      </div>`;
    const buyBtn = col.querySelector('.buy');
    if (buyBtn) buyBtn.addEventListener('click', () => buy(p.id, buyBtn));
    productsBox.appendChild(col);
  }
}

async function load() {
  try {
    const shop = await api('/api/shop', 'GET');
    render(shop);
  } catch (err) { showMsg('msg', err.message, 'danger'); }
}

async function buy(productId, btn) {
  btn.disabled = true;
  try {
    const res = await api('/api/buy', 'POST', { product_id: productId });
    const isFlag = productId === 'flag';
    let html = `<div class="alert alert-${isFlag ? 'success' : 'info'}">
      <strong>${escapeHtml(res.name)}:</strong>
      <div class="${isFlag ? 'font-monospace mt-2' : 'mt-1'}">${escapeHtml(res.message)}</div>
    </div>`;
    document.getElementById('msg').innerHTML = html;
    await load();
    renderAuthNav();
  } catch (err) {
    showMsg('msg', err.message, 'danger');
    btn.disabled = false;
  }
}

if (!getToken()) {
  location.href = '/login';
} else {
  load();
}
