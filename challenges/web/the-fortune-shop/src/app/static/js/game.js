// Game page: fetch a seed, start a round, answer one option per question,
// submit. Requires auth; redirects to /login otherwise.
let state = { gameId: null, questions: [], answers: {} };

const qBox = document.getElementById('questions');
const countEl = document.getElementById('count');
const submitBtn = document.getElementById('submit');
const newBtn = document.getElementById('new-game');
const seedLine = document.getElementById('seed-line');

function refreshCount() {
  const n = Object.keys(state.answers).length;
  countEl.textContent = n;
  submitBtn.disabled = n !== state.questions.length;
}

function renderQuestions(questions) {
  qBox.innerHTML = '';
  for (const q of questions) {
    const card = document.createElement('div');
    card.className = 'card bg-body-tertiary border-secondary-subtle';
    const opts = q.options.map((opt) => {
      const rid = `q${q.id}_${opt}`.replace(/[^a-zA-Z0-9_]/g, '_');
      return `
        <div class="col">
          <input type="radio" class="btn-check" name="q${q.id}" id="${rid}" value="${escapeHtml(opt)}" autocomplete="off">
          <label class="btn btn-outline-light w-100 text-start" for="${rid}">${escapeHtml(opt)}</label>
        </div>`;
    }).join('');
    card.innerHTML = `
      <div class="card-body">
        <h5 class="card-title mb-3">${escapeHtml(q.label)}</h5>
        <div class="row row-cols-1 row-cols-sm-2 row-cols-lg-3 g-2">${opts}</div>
      </div>`;
    card.querySelectorAll(`input[name="q${q.id}"]`).forEach((inp) => {
      inp.addEventListener('change', () => { state.answers[q.id] = inp.value; refreshCount(); });
    });
    qBox.appendChild(card);
  }
}

async function newGame() {
  showMsg('msg', 'Генерируем раунд…', 'info');
  try {
    const cfg = await api('/api/get_config', 'GET');
    const game = await api('/api/start_game', 'POST', { seed: cfg.seed });
    state = { gameId: game.game_id, questions: game.questions, answers: {} };
    seedLine.textContent = `game #${game.game_id} · seed ${game.seed}`;
    renderQuestions(game.questions);
    refreshCount();
    document.getElementById('msg').innerHTML = '';
  } catch (err) { showMsg('msg', err.message, 'danger'); }
}

async function submit() {
  if (!state.gameId) return;
  submitBtn.disabled = true;
  // Order answers by question id.
  const guesses = state.questions.map((q) => state.answers[q.id]);
  try {
    const res = await api('/api/submit', 'POST', { game_id: state.gameId, guesses });
    const tail = `Верных: ${res.correct_count}/${state.questions.length} · +${res.score} очков · баланс: ${res.balance}.`;
    if (res.correct) {
      showMsg('msg', `Идеальный раунд! ${tail} Загляни в магазин.`, 'success');
    } else {
      showMsg('msg', `${tail}`, 'warning');
    }
    qBox.querySelectorAll('input').forEach((i) => { i.disabled = true; });
    renderAuthNav();
  } catch (err) { showMsg('msg', err.message, 'danger'); submitBtn.disabled = false; }
}

if (!getToken()) {
  location.href = '/login';
} else {
  newBtn.addEventListener('click', newGame);
  submitBtn.addEventListener('click', submit);
  newGame();
}
