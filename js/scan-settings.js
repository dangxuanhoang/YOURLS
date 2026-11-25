// Scan settings page: show/hide key, test a saved key through admin-ajax.php (action scan_test)
(function () {
    document.addEventListener('click', function (e) {
        var t = e.target;
        if (!t || !t.closest) return;
        var tog = t.closest('.toggle-key');
        if (tog) {
            var input = document.getElementById(tog.getAttribute('data-target'));
            if (input) {
                var show = input.type === 'password';
                input.type = show ? 'text' : 'password';
                tog.textContent = show ? 'Hide' : 'Show';
            }
            return;
        }
        var test = t.closest('.test-key');
        if (test) {
            var svc = test.getAttribute('data-service');
            var out = document.getElementById('test-' + svc);
            out.hidden = false;
            out.className = 'test-result';
            out.textContent = '…';
            test.disabled = true;
            fetch(ajaxurl + '?action=scan_test&service=' + encodeURIComponent(svc) + '&nonce=' + encodeURIComponent(window.scanTestNonce || ''), { cache: 'no-store', credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    out.className = 'test-result ' + (res.status === 'ok' ? 'ok' : (res.status === 'error' ? 'bad' : 'warn'));
                    out.textContent = (res.status === 'ok' ? '✓ ' : '✕ ') + (res.message || '');
                })
                .catch(function () { out.className = 'test-result bad'; out.textContent = '✕ Request failed'; })
                .then(function () { test.disabled = false; });
        }
    });
})();
