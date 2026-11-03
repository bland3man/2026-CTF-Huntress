/* Progressive enhancement only: everything works without this file. */
(function () {
  'use strict';

  function toast(msg) {
    var t = document.createElement('div');
    t.className = 'copied';
    t.setAttribute('role', 'status');
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 1400);
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); resolve(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }

  /* Flag chips: reveal copy buttons (hidden for no-JS readers). */
  var btns = document.querySelectorAll('.flag .fc');
  for (var i = 0; i < btns.length; i++) {
    btns[i].hidden = false;
    btns[i].addEventListener('click', function (ev) {
      var chip = ev.currentTarget.closest('.flag');
      var val = chip ? chip.querySelector('.fv') : null;
      if (!val) return;
      copyText(val.textContent).then(function () { toast('Transmission copied'); },
        function () { toast('Copy unavailable'); });
    });
  }

  /* Challenge search + lane filter. */
  var box = document.querySelector('[data-search-box]');
  if (!box) return;
  box.hidden = false;
  var input = box.querySelector('input');
  var buttons = box.querySelectorAll('[data-lane]');
  var items = document.querySelectorAll('[data-search]');
  var counter = document.querySelector('[data-count]');
  var lane = 'all';

  function apply() {
    var q = (input.value || '').toLowerCase().trim().split(/\s+/).filter(Boolean);
    var shown = 0;
    for (var j = 0; j < items.length; j++) {
      var it = items[j];
      var hay = it.getAttribute('data-search');
      var okLane = lane === 'all' || it.getAttribute('data-lane') === lane;
      var okQ = q.every(function (w) { return hay.indexOf(w) !== -1; });
      var show = okLane && okQ;
      it.hidden = !show;
      if (show) shown++;
    }
    if (counter) counter.textContent = shown + ' / ' + items.length + ' contacts';
  }
  input.addEventListener('input', apply);
  for (var k = 0; k < buttons.length; k++) {
    buttons[k].addEventListener('click', function (ev) {
      lane = ev.currentTarget.getAttribute('data-lane');
      for (var m = 0; m < buttons.length; m++) {
        buttons[m].setAttribute('aria-pressed', buttons[m] === ev.currentTarget ? 'true' : 'false');
      }
      apply();
    });
  }
  var params = new URLSearchParams(window.location.search);
  if (params.get('q')) { input.value = params.get('q'); }
  apply();
})();
