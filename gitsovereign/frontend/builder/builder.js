// GitSovereign — dashboard/page builder.
// Layout is device-local only and can be exported as static HTML.

const WIDGET_LABELS = {
  chat: 'Chat panel — connects to your configured local/remote model routes',
  voice: 'Voice control — mic + Piper TTS output',
  chart: 'Chart — renders from a data source you configure',
  'repo-status': 'Repo status — reads your connected git remote',
  'evidence-feed': 'Evidence feed — live append-only ledger view',
  markdown: 'Markdown block — static content',
};

const STORAGE_KEY = 'gitsovereign:builder:layout';

function loadLayout() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
    return Array.isArray(value) ? value.filter((item) => Object.hasOwn(WIDGET_LABELS, item)) : [];
  } catch {
    return [];
  }
}

function saveLayout(layout) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
}

function renderCanvas(canvas, layout) {
  canvas.replaceChildren();
  layout.forEach((widgetType, index) => {
    const element = document.createElement('div');
    element.className = 'placed-widget';
    element.draggable = true;
    element.dataset.index = String(index);
    element.textContent = WIDGET_LABELS[widgetType];
    element.addEventListener('dragstart', (event) => {
      event.dataTransfer.setData('text/plain', JSON.stringify({ move: index }));
    });
    canvas.appendChild(element);
  });
}

function buildStaticPage(layout) {
  const body = layout
    .map((widget) => `<section data-widget="${widget}"><!-- ${WIDGET_LABELS[widget]} --></section>`)
    .join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>GitSovereign exported page</title></head>
<body>
${body}
</body></html>
`;
}

function initBuilder() {
  const canvas = document.getElementById('builder-canvas');
  const exportButton = document.getElementById('builder-export');
  if (!canvas) return;

  let layout = loadLayout();
  renderCanvas(canvas, layout);

  document.querySelectorAll('.widget-chip').forEach((chip) => {
    chip.addEventListener('dragstart', (event) => {
      event.dataTransfer.setData('text/plain', JSON.stringify({ add: chip.dataset.widget }));
    });
  });

  canvas.addEventListener('dragover', (event) => {
    event.preventDefault();
    canvas.classList.add('drag-over');
  });

  canvas.addEventListener('dragleave', () => canvas.classList.remove('drag-over'));

  canvas.addEventListener('drop', (event) => {
    event.preventDefault();
    canvas.classList.remove('drag-over');
    let data;
    try {
      data = JSON.parse(event.dataTransfer.getData('text/plain') || '{}');
    } catch {
      return;
    }

    if (data.add && Object.hasOwn(WIDGET_LABELS, data.add)) {
      layout.push(data.add);
      saveLayout(layout);
      renderCanvas(canvas, layout);
    }
  });

  exportButton?.addEventListener('click', () => {
    const blob = new Blob([buildStaticPage(layout)], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'gitsovereign-export.html';
    anchor.click();
    URL.revokeObjectURL(url);
  });
}

document.addEventListener('DOMContentLoaded', initBuilder);

export { loadLayout, saveLayout, buildStaticPage };
