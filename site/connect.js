// zeusi.ai: progressive enhancement for the "Connect your AI" section.
// Copy buttons and the app picker tabs (WAI-ARIA tabs pattern). Same origin, no network,
// no third party, no HTML injection. Without this file every panel shows, stacked, and the
// URL and commands stay selectable.
(function () {
  'use strict';

  var status = document.getElementById('copy-status');

  function announce(message) {
    if (!status) return;
    status.textContent = '';
    window.setTimeout(function () { status.textContent = message; }, 50);
  }

  function selectText(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    if (!sel) return false;
    sel.removeAllRanges();
    sel.addRange(range);
    return true;
  }

  function fallbackCopy(el) {
    if (!selectText(el)) return false;
    try {
      return document.execCommand('copy');
    } catch (e) {
      return false;
    }
  }

  function flash(button, label) {
    button.textContent = label;
    window.clearTimeout(button._zeusiTimer);
    button._zeusiTimer = window.setTimeout(function () { button.textContent = 'Copy'; }, 2000);
  }

  function copyFrom(button) {
    var target = document.getElementById(button.getAttribute('data-copy'));
    if (!target) return;
    var text = target.textContent;
    var done = function () { flash(button, 'Copied'); announce('Copied'); };
    var fallback = function () {
      if (fallbackCopy(target)) done();
      else announce('Selected. Press Ctrl+C or Command+C to copy.');
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  var buttons = document.querySelectorAll('button.copy[data-copy]');
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].hidden = false;
    buttons[i].addEventListener('click', function (ev) { copyFrom(ev.currentTarget); });
  }

  var groups = document.querySelectorAll('[data-tabs]');
  for (var g = 0; g < groups.length; g++) setupTabs(groups[g]);

  function setupTabs(root) {
    var list = root.querySelector('[role="tablist"]');
    if (!list) return;
    var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
    var panels = tabs.map(function (t) { return document.getElementById(t.getAttribute('aria-controls')); });
    if (tabs.length === 0 || panels.indexOf(null) !== -1) return;
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function select(index, focus) {
      for (var k = 0; k < tabs.length; k++) {
        var on = k === index;
        tabs[k].setAttribute('aria-selected', on ? 'true' : 'false');
        tabs[k].tabIndex = on ? 0 : -1;
        panels[k].hidden = !on;
      }
      if (focus) {
        tabs[index].focus();
        if (tabs[index].scrollIntoView) tabs[index].scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: reduce ? 'auto' : 'smooth' });
      }
    }

    var start = 0;
    for (var s = 0; s < tabs.length; s++) if (tabs[s].getAttribute('aria-selected') === 'true') start = s;
    list.hidden = false;
    root.classList.add('tabs-ready');
    select(start, false);

    list.addEventListener('click', function (ev) {
      var tab = ev.target.closest ? ev.target.closest('[role="tab"]') : null;
      var idx = tabs.indexOf(tab);
      if (idx !== -1) select(idx, true);
    });

    list.addEventListener('keydown', function (ev) {
      var current = tabs.indexOf(document.activeElement);
      if (current === -1) return;
      var next = null;
      if (ev.key === 'ArrowRight') next = (current + 1) % tabs.length;
      else if (ev.key === 'ArrowLeft') next = (current - 1 + tabs.length) % tabs.length;
      else if (ev.key === 'Home') next = 0;
      else if (ev.key === 'End') next = tabs.length - 1;
      if (next === null) return;
      ev.preventDefault();
      select(next, true);
    });
  }
})();
