// Trang quét URL độc hại: chạy lần lượt từng bước kiểm tra qua yourls-scan.php, hiện tiến trình, rồi cho phép tiếp tục.
(function () {
    var card = document.getElementById('scan');
    if (!card) return;
    var cfg = {};
    try { cfg = JSON.parse(card.getAttribute('data-config')); } catch (e) { return; }
    var T = cfg.i18n || {};
    var ids = Object.keys(cfg.steps || {});
    var results = {};
    var MAX_POLLS = 25, POLL_MS = 2500;

    var $ = function (id) { return document.getElementById(id); };
    var bar = $('scan-bar'), progress = card.querySelector('.scan-progress');

    function li(step) { return card.querySelector('li[data-step="' + step + '"]'); }
    function setStep(step, cls, note) {
        var el = li(step);
        if (!el) return;
        el.className = cls;
        el.querySelector('.note').textContent = note || '';
    }
    function setProgress(done, extra) {
        var pct = Math.min(100, Math.round(((done + (extra || 0)) / ids.length) * 100));
        bar.style.width = pct + '%';
        progress.setAttribute('aria-valuenow', pct);
    }
    function call(step, id) {
        var url = cfg.endpoint + '?keyword=' + encodeURIComponent(cfg.keyword) + '&step=' + encodeURIComponent(step) + (id ? '&id=' + encodeURIComponent(id) : '');
        return fetch(url, { cache: 'no-store', credentials: 'same-origin' }).then(function (r) { return r.json(); });
    }
    function sleep(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }

    // One check; VirusTotal-like checks answer "pending" with an id that is polled until completed
    async function runStep(step) {
        setStep(step, 'running', T.running);
        var res;
        try {
            res = await call(step);
            var polls = 0;
            while (res.status === 'pending' && polls < MAX_POLLS) {
                polls++;
                setProgress(Object.keys(results).length, Math.min(0.9, polls / MAX_POLLS));
                setStep(step, 'running', res.message);
                await sleep(POLL_MS);
                res = await call(step === 'vt' ? 'vt_poll' : step, res.id);
            }
            if (res.status === 'pending') res = { status: 'error', message: T.timeout };
        } catch (e) {
            res = { status: 'error', message: T.failed };
        }
        results[step] = res;
        setStep(step, res.status, res.message);
        setProgress(Object.keys(results).length);
        return res;
    }

    function finish() {
        var statuses = ids.map(function (s) { return results[s].status; });
        var state = statuses.indexOf('threat') !== -1 ? 'threat'
                  : (statuses.indexOf('warn') !== -1 || statuses.indexOf('error') !== -1) ? 'warn' : 'ok';
        document.body.className = 'state-' + state;
        card.className = 'scan-card state-' + state;
        var icon = $('scan-icon');
        icon.textContent = state === 'ok' ? '✓' : (state === 'warn' ? '!' : '✕');
        $('scan-title').textContent = state === 'ok' ? T.safe : (state === 'warn' ? T.caution : T.threat);
        $('scan-text').textContent = state === 'ok' ? T.safeText : (state === 'warn' ? T.cautionText : T.threatText);
        bar.style.width = '100%';
        $('scan-actions').hidden = false;
        if (state === 'threat') {
            $('scan-continue').style.display = 'none';
            $('scan-back').className = 'btn primary';
            $('scan-force').hidden = false;
        } else {
            $('scan-continue').focus();
        }
    }

    async function run() {
        for (var i = 0; i < ids.length; i++) {
            var r = await runStep(ids[i]);
            if (r.status === 'threat') {
                // no need to run the remaining checks: mark them as skipped
                for (var j = i + 1; j < ids.length; j++) { results[ids[j]] = { status: 'ok', message: '' }; setStep(ids[j], 'pending', ''); }
                break;
            }
        }
        finish();
    }
    run();
})();
