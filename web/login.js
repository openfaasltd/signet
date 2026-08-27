(function () {
  'use strict';
  var startBtn = document.getElementById('ghStart');
  if (!startBtn) return;

  var cfgEl = document.querySelector('meta[name="gh-params"]');
  if (!cfgEl) return;
  var P = {};
  try { P = JSON.parse(atob(cfgEl.getAttribute('content'))); } catch (e) { P = {}; }

  var loginForm = document.getElementById('loginForm');
  var devPanel = document.getElementById('ghDevice');
  var donePanel = document.getElementById('ghDone');
  var failPanel = document.getElementById('ghFail');
  var codeEl = document.getElementById('ghCode');
  var linkEl = document.getElementById('ghLink');
  var expEl = document.getElementById('ghExp');
  var failMsg = document.getElementById('ghFailMsg');
  var hint = document.getElementById('ghHint');
  var id = '', pollTimer = null, cdTimer = null, started = false;

  function post(p, path) {
    return fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p || {}), credentials: 'same-origin' });
  }
  function showLogin() { loginForm.style.display = ''; startBtn.style.display = ''; devPanel.style.display = 'none'; donePanel.style.display = 'none'; failPanel.style.display = 'none'; hint.style.display = 'none'; }
  function showPanel() { loginForm.style.display = 'none'; startBtn.style.display = 'none'; failPanel.style.display = 'none'; donePanel.style.display = 'none'; devPanel.style.display = 'block'; hint.style.display = 'block'; }
  function showDone(redir) { clearInterval(pollTimer); clearInterval(cdTimer); loginForm.style.display = 'none'; startBtn.style.display = 'none'; devPanel.style.display = 'none'; failPanel.style.display = 'none'; donePanel.style.display = 'block'; hint.style.display = 'none'; window.setTimeout(function () { if (redir) window.location.assign(redir); }, 1200); }
  function showFail(reason) { clearInterval(pollTimer); clearInterval(cdTimer); loginForm.style.display = 'none'; startBtn.style.display = 'none'; devPanel.style.display = 'none'; donePanel.style.display = 'none'; failPanel.style.display = 'block'; hint.style.display = 'none'; failMsg.textContent = reason || 'GitHub login failed. Try again.'; }
  function fmt(sec) { sec = Math.max(0, Math.floor(sec)); var m = Math.floor(sec / 60); var s = sec % 60; return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s; }
  function countdown(from) { var end = Date.now() + (from || 900) * 1000; var tick = function () { var left = Math.round((end - Date.now()) / 1000); expEl.textContent = fmt(left); if (left <= 0) clearInterval(cdTimer); }; tick(); cdTimer = setInterval(tick, 1000); }

  document.getElementById('ghCopy').addEventListener('click', function () {
    var b = this, t = codeEl.textContent;
    if (navigator.clipboard) navigator.clipboard.writeText(t).then(function () { b.textContent = 'Copied'; window.setTimeout(function () { b.textContent = 'Copy'; }, 1200); }).catch(function () {});
  });
  document.getElementById('ghCancel').addEventListener('click', function () { clearInterval(pollTimer); clearInterval(cdTimer); if (id) post({ id: id }, '/auth/github/device/cancel'); showLogin(); });

  function poll() {
    if (!id) return;
    post({ id: id }, '/auth/github/device/status').then(function (r) {
      if (r.status === 200) return r.json().then(function (d) { showDone(d.redirect_url); });
      if (r.status === 202) return r.json().then(function (d) { pollTimer = window.setTimeout(poll, (d.retry_after || 5) * 1000); });
      showFail(r.status === 410 ? 'The code expired. Start again to get a new one.' : (r.status === 403 ? 'Your GitHub identity is not authorized for this Signet.' : 'GitHub login failed. Try again.'));
    }).catch(function () { pollTimer = window.setTimeout(poll, 4000); });
  }

  startBtn.addEventListener('click', function () {
    startBtn.disabled = true; startBtn.textContent = 'Starting GitHub…';
    post(P, '/auth/github/device').then(function (r) {
      return r.json().then(function (d) {
        if (r.status !== 200 || !d || !d.id) throw new Error('ghstart');
        id = d.id; var u = d.verification_uri || 'https://github.com/login/device';
        codeEl.textContent = d.user_code || '----';
        linkEl.textContent = u.replace(/^https?:\/\//, ''); linkEl.href = u;
        started = true;
        showPanel();
        countdown(d.expires_in || 900);
        poll();
      });
    }).catch(function () { startBtn.disabled = false; startBtn.textContent = 'Sign in with GitHub'; if (started) showFail('Could not complete the sign-in.'); else showLogin(); });
  });
})();
