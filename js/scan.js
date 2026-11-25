// Scan page: runs the checks one by one against yourls-scan.php, shows the progress, then lets the visitor continue.
// English / Vietnamese: texts come from the dictionary sent by the server (same keys as yourls_scan_dictionary()), so
// switching language does not reload the page (a reload would count one more click).
(function () {
    var card = document.getElementById('scan');
    if (!card) return;
    var cfg = {};
    try { cfg = JSON.parse(card.getAttribute('data-config')); } catch (e) { return; }
    var ids = cfg.steps || [];
    var results = {};          // step -> last result
    var state = null;          // 'ok' | 'warn' | 'threat' once finished
    var lang = cfg.lang === 'vi' ? 'vi' : 'en';
    var MAX_POLLS = 25, POLL_MS = 2500;
    var countdown = null;      // { left, timer } while the automatic redirect is pending

    var $ = function (id) { return document.getElementById(id); };
    var bar = $('scan-bar'), progress = card.querySelector('.scan-progress');

    // ---- i18n -----------------------------------------------------------------------------------------------
    function t(key, args) {
        var text = (cfg.dict[lang] && cfg.dict[lang][key]) || (cfg.dict.en && cfg.dict.en[key]) || key;
        (args || []).forEach(function (v, i) { text = text.split('{' + i + '}').join(String(v)); });
        return text;
    }
    // Same algorithm as yourls_scan_message() in PHP
    function render(res) {
        if (!res || !res.key) return (res && res.message) || '';
        var text = t(res.key, res.args);
        if (res.list) {
            var joined = res.list.codes.map(function (c) { return t(res.list.prefix + c); }).join(res.list.sep || ', ');
            if (res.list.ucfirst) joined = joined.charAt(0).toUpperCase() + joined.slice(1);
            text = text.split('{list}').join(joined);
        }
        return text;
    }
    function footer() {
        var holder = $('scan-foot');
        if (!holder) return;
        var sep = ' ' + t('and') + ' ';
        var tpl = t('protected', ['\u0000']).split('\u0000');
        holder.textContent = '';
        holder.appendChild(document.createTextNode(tpl[0]));
        (cfg.services || []).forEach(function (s, i) {
            if (i) holder.appendChild(document.createTextNode(sep));
            var a = document.createElement('a');
            a.href = s.url; a.target = '_blank'; a.rel = 'noopener'; a.textContent = s.name;
            holder.appendChild(a);
        });
        holder.appendChild(document.createTextNode(tpl[1] || ''));
    }
    function applyLang() {
        document.documentElement.lang = lang;
        var nodes = card.querySelectorAll('[data-i18n]');
        for (var i = 0; i < nodes.length; i++) nodes[i].textContent = t(nodes[i].getAttribute('data-i18n'));
        // Result notes of the steps already run
        ids.forEach(function (s) {
            var el = li(s);
            if (el && results[s]) el.querySelector('.note').textContent = noteFor(s);
        });
        var btns = card.querySelectorAll('.scan-lang button');
        for (var j = 0; j < btns.length; j++) btns[j].setAttribute('aria-pressed', btns[j].getAttribute('data-lang') === lang ? 'true' : 'false');
        if (countdown) showCountdown();
        if (state) showState(); else { $('scan-title').textContent = t('title_scanning'); $('scan-text').textContent = t('text_scanning'); }
        footer();
        document.title = t('page_title') + ' — ' + document.title.split(' — ').pop();
    }
    function setLang(l) {
        lang = l;
        try { document.cookie = 'yourls_scan_lang=' + l + ';path=/;max-age=31536000;SameSite=Lax'; } catch (e) {}
        applyLang();
    }
    card.querySelector('.scan-lang').addEventListener('click', function (e) {
        var b = e.target.closest ? e.target.closest('button[data-lang]') : null;
        if (b) setLang(b.getAttribute('data-lang'));
    });

    // ---- steps ----------------------------------------------------------------------------------------------
    function li(step) { return card.querySelector('li[data-step="' + step + '"]'); }
    function noteFor(step) {
        var r = results[step];
        if (!r) return '';
        if (r.local) return t(r.local);          // client side messages (running, timeout, failed)
        return render(r);
    }
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
        var url = cfg.endpoint + '?keyword=' + encodeURIComponent(cfg.keyword) + '&step=' + encodeURIComponent(step) + '&lang=' + lang + (id ? '&id=' + encodeURIComponent(id) : '');
        return fetch(url, { cache: 'no-store', credentials: 'same-origin' }).then(function (r) { return r.json(); });
    }
    function sleep(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }

    // One check; VirusTotal-like checks answer "pending" with an id that is polled until completed
    async function runStep(step) {
        results[step] = { status: 'running', local: 'running' };
        setStep(step, 'running', t('running'));
        var res;
        try {
            res = await call(step);
            var polls = 0;
            while (res.status === 'pending' && polls < MAX_POLLS) {
                polls++;
                setProgress(doneCount(), Math.min(0.9, polls / MAX_POLLS));
                results[step] = res;
                setStep(step, 'running', render(res));
                await sleep(POLL_MS);
                res = await call(step === 'vt' ? 'vt_poll' : step, res.id);
            }
            if (res.status === 'pending') res = { status: 'error', local: 'timeout' };
        } catch (e) {
            res = { status: 'error', local: 'failed' };
        }
        results[step] = res;
        setStep(step, res.status, noteFor(step));
        setProgress(doneCount());
        return res;
    }
    function doneCount() {
        return ids.filter(function (s) { return results[s] && results[s].status !== 'running' && results[s].status !== 'pending'; }).length;
    }

    // ---- final state ----------------------------------------------------------------------------------------
    function showState() {
        var icon = $('scan-icon');
        icon.textContent = state === 'ok' ? '✓' : (state === 'warn' ? '!' : '✕');
        $('scan-title').textContent = state === 'ok' ? t('safe') : (state === 'warn' ? t('caution') : t('threat'));
        $('scan-text').textContent = state === 'ok' ? t('safe_text') : (state === 'warn' ? t('caution_text') : t('threat_text'));
    }
    // Automatic redirect after N seconds when no threat was found (the visitor can stop it)
    function showCountdown() {
        $('scan-countdown-text').textContent = t('redirecting', [countdown.left]);
    }
    function startCountdown() {
        var secs = parseInt(cfg.autoredirect, 10) || 0;
        if (secs <= 0) return;
        countdown = { left: secs, timer: null };
        $('scan-countdown').hidden = false;
        showCountdown();
        countdown.timer = setInterval(function () {
            countdown.left--;
            if (countdown.left <= 0) {
                clearInterval(countdown.timer);
                window.location.href = $('scan-continue').href;
                return;
            }
            showCountdown();
        }, 1000);
    }
    function stopCountdown() {
        if (!countdown) return;
        clearInterval(countdown.timer);
        countdown = null;
        $('scan-countdown').hidden = true;
    }
    $('scan-stay').addEventListener('click', stopCountdown);
    function finish() {
        var statuses = ids.map(function (s) { return results[s] ? results[s].status : 'ok'; });
        state = statuses.indexOf('threat') !== -1 ? 'threat'
              : (statuses.indexOf('warn') !== -1 || statuses.indexOf('error') !== -1) ? 'warn' : 'ok';
        document.body.className = 'state-' + state;
        card.className = 'scan-card state-' + state;
        showState();
        bar.style.width = '100%';
        $('scan-actions').hidden = false;
        if (state === 'threat') {
            $('scan-continue').style.display = 'none';
            $('scan-back').className = 'btn primary';
            $('scan-force').hidden = false;
        } else {
            $('scan-continue').focus();
            if (state === 'ok') startCountdown(); // nothing found: continue automatically; with notes/errors the visitor decides
        }
    }

    async function run() {
        for (var i = 0; i < ids.length; i++) {
            var r = await runStep(ids[i]);
            if (r.status === 'threat') break; // no need to run the remaining checks
        }
        finish();
    }
    applyLang();
    run();
})();
