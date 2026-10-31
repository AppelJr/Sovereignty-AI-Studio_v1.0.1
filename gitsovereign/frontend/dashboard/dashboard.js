// GitSovereign — dashboard shell logic.
// Same-origin API only. The dashboard observes evidence; it does not grant authority.

const VIEWS = ['dashboard', 'builder', 'voice', 'repos', 'evidence'];

function switchView(name) {
  if (!VIEWS.includes(name)) return;
  for (const view of VIEWS) {
    const element = document.getElementById(`view-${view}`);
    if (element) element.style.display = view === name ? '' : 'none';
  }
  document.querySelectorAll('.nav-item').forEach((element) => {
    element.classList.toggle('active', element.dataset.view === name);
  });
}

document.querySelectorAll('.nav-item').forEach((element) => {
  element.addEventListener('click', () => switchView(element.dataset.view));
});

function escapeHTML(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderSeal(status, reason) {
  const allowed = status === 'allowed';
  const cls = allowed ? 'seal' : 'seal denied';
  const label = allowed ? 'VERIFIED' : 'DENIED';
  return `<span class="${cls}">${label} — ${escapeHTML(reason || '')}</span>`;
}

function renderEvents(events) {
  return events.map((event) => `
    <div class="evidence-row">
      <span>${escapeHTML(event.action || event.event || 'event')}</span>
      ${renderSeal(event.decision, event.reason)}
    </div>`).join('');
}

async function pollEvidence() {
  try {
    const response = await fetch('/api/evidence/recent', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const events = await response.json();
    if (!Array.isArray(events)) throw new Error('invalid evidence response');

    document.getElementById('stat-evidence').textContent = `${events.length} events`;
    document.getElementById('net-status').textContent = 'connected';

    const html = renderEvents(events.slice(0, 8));
    document.getElementById('dashboard-evidence-feed').innerHTML = html || '<p style="color:var(--muted)">No events yet.</p>';
    document.getElementById('evidence-full-feed').innerHTML = html || '<p style="color:var(--muted)">No events yet.</p>';
  } catch {
    document.getElementById('net-status').textContent = 'backend offline (local shell only)';
  }
}

document.getElementById('stat-runtime').textContent = navigator.onLine ? 'browser online' : 'browser offline';
pollEvidence();
setInterval(pollEvidence, 5000);

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/service-worker.js').catch(() => {});
}

export { switchView, pollEvidence };
