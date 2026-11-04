(function () {
  'use strict';

  var pages = {
    dashboard: renderDashboard,
    podcast: renderPodcast,
    presentation: renderPresentation,
    story: renderStory,
    social: renderSocial,
    writing: renderWriting,
    alerts: renderAlerts
  };

  var state = {
    page: 'dashboard'
  };

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'className') node.className = attrs[k];
        else if (k === 'text') node.textContent = attrs[k];
        else if (k.slice(0, 2) === 'on') node.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function card(title, body) {
    var c = el('div', { className: 'card' });
    if (title) c.appendChild(el('h2', { text: title }));
    if (body) c.appendChild(body);
    return c;
  }

  function renderDashboard() {
    var root = el('div', { id: 'page-dashboard' });
    root.appendChild(card('Dashboard', el('p', { className: 'muted', text: 'Sovereignty AI Studio — KODER dashboard. Local-first. No cloud.' })));
    root.appendChild(card('Runtime', el('p', { text: 'Mode: LOCAL (default). HYBRID and ONLINE require explicit owner authorization.' })));
    root.appendChild(card('Stack', el('p', { text: 'Vanilla HTML/CSS/JS. System fonts only. No React, no Next, no Vercel, no Firebase, no Tailwind, no third-party CDNs.' })));
    return root;
  }

  function renderPodcast() {
    return card('Podcast', el('p', { text: 'Podcast generator — coming soon.' }));
  }
  function renderPresentation() {
    return card('Presentation', el('p', { text: 'Presentation builder — coming soon.' }));
  }
  function renderStory() {
    return card('Story', el('p', { text: 'Story generator — coming soon.' }));
  }
  function renderSocial() {
    return card('Social', el('p', { text: 'Social campaign — coming soon.' }));
  }
  function renderWriting() {
    return card('Writing', el('p', { text: 'Writing assistant — coming soon.' }));
  }
  function renderAlerts() {
    return card('Alerts', el('p', { text: 'Alert feed — coming soon.' }));
  }

  function navigate(page) {
    state.page = page;
    var main = document.getElementById('app');
    main.innerHTML = '';
    var render = pages[page] || pages.dashboard;
    main.appendChild(render());
    var links = document.querySelectorAll('.app-nav a);
    for (var i = 0; i < links.length; i++) {
      links[i].classList.toggle('active', links[i].getAttribute('data-page') === page);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var nav = document.querySelectorAll('.app-nav a[data-page]');
    for (var i = 0; i < nav.length; i++) {
      nav[i].addEventListener('click', function (e) {
        e.preventDefault();
        navigate(this.getAttribute('data-page'));
      });
    }
    navigate(state.page);
  });
})();
