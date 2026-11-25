<?php

/**
 * Malicious URL scan.
 *
 * Before a visitor is sent to the long URL, an interstitial page shows the progress of a scan of that URL and only
 * lets the visitor continue if nothing malicious is found. Checks, run one after the other from the browser
 * (see js/scan.js and yourls-scan.php):
 *   - "heuristic": offline checks of the URL itself (always available)
 *   - "gsb"      : Google Safe Browsing (free API key: define YOURLS_SCAN_GSB_KEY in config.php)
 *   - "vt"       : VirusTotal (free API key: define YOURLS_SCAN_VT_KEY in config.php)
 * The scanned URL is never fetched by this server: only its address is sent to those services.
 *
 * Settings: the admin page "Scan settings" (admin/scan-settings.php), or constants in config.php which take precedence:
 * YOURLS_URL_SCAN (bool, default true), YOURLS_SCAN_GSB_KEY, YOURLS_SCAN_VT_KEY.
 * Results are cached in a small table created on first use (like link metadata).
 */

/**
 * Is the scan interstitial enabled ?
 *
 * @return bool
 */
function yourls_scan_enabled():bool {
    if( defined( 'YOURLS_URL_SCAN' ) ) {
        $enabled = (bool) YOURLS_URL_SCAN;                      // config.php wins
    } else {
        $enabled = yourls_get_option( 'scan_enabled', '1' ) !== '0'; // settings page, default on
    }
    return (bool) yourls_apply_filter( 'scan_enabled', $enabled );
}

/**
 * API key of a scan service: constant in config.php (wins) or value saved in the settings page
 *
 * @param  string $service  gsb | vt
 * @return array            [ key, source ] where source is 'config', 'saved' or '' (not set)
 */
function yourls_scan_key_info( $service ):array {
    $const = [ 'gsb' => 'YOURLS_SCAN_GSB_KEY', 'vt' => 'YOURLS_SCAN_VT_KEY' ][ $service ] ?? '';
    if( $const && defined( $const ) && constant( $const ) ) {
        return [ (string) constant( $const ), 'config' ];
    }
    $saved = (string) yourls_get_option( 'scan_' . $service . '_key', '' );
    return $saved !== '' ? [ $saved, 'saved' ] : [ '', '' ];
}

/**
 * @param  string $service  gsb | vt
 * @return string           API key, or empty string
 */
function yourls_scan_key( $service ):string {
    return yourls_scan_key_info( $service )[0];
}

/**
 * Is a provider used by the scan ? It needs an API key AND must not be switched off in the settings page
 * (option scan_<service>_enabled, on by default).
 *
 * @param  string $service  gsb | vt
 * @return bool
 */
function yourls_scan_provider_enabled( $service ):bool {
    return yourls_scan_key( $service ) !== '' && yourls_get_option( 'scan_' . $service . '_enabled', '1' ) !== '0';
}

/**
 * List of the checks that will run, as [ id => label ]
 *
 * @return array
 */
function yourls_scan_checks():array {
    $checks = [ 'heuristic' => yourls_scan_t( 'step_heuristic' ) ];
    if( yourls_scan_provider_enabled( 'gsb' ) ) {
        $checks['gsb'] = yourls_scan_t( 'step_gsb' );
    }
    if( yourls_scan_provider_enabled( 'vt' ) ) {
        $checks['vt'] = yourls_scan_t( 'step_vt' );
    }
    return yourls_apply_filter( 'scan_checks', $checks );
}

/* ------------------------------------------------------------------- i18n */

/**
 * Texts of the scan page, in English and Vietnamese. Placeholders are {0}, {1}, ... and {list}.
 * The same dictionary is sent to js/scan.js, so that visitors can switch language without reloading the page
 * (reloading would count one more click).
 *
 * @return array  [ lang => [ key => text ] ]
 */
function yourls_scan_dictionary():array {
    static $dict = null;
    if( $dict !== null ) {
        return $dict;
    }
    $dict = [
        'en' => [
            'page_title' => 'Scanning link', 'title_scanning' => 'Scanning the link…',
            'text_scanning' => 'We are checking this link for malware and phishing before you continue.',
            'destination' => 'Destination',
            'safe' => 'No threat found', 'safe_text' => 'This link looks safe. You can continue.',
            'caution' => 'Proceed with caution', 'caution_text' => 'No threat was confirmed, but some checks raised notes or could not complete.',
            'threat' => 'Dangerous link blocked', 'threat_text' => 'This link was flagged as malicious. Continuing is strongly discouraged.',
            'running' => 'Running…', 'timeout' => 'Analysis is taking too long', 'failed' => 'Check failed',
            'continue' => 'Continue to the website', 'back' => 'Go back',
            'risk' => 'I understand the risk', 'force' => 'Continue anyway (not recommended)',
            'noscript' => 'JavaScript is required to scan this link.', 'noscript_go' => 'Continue without scanning',
            'protected' => 'Protected by {0}', 'and' => 'and', 'language' => 'Language',
            'step_heuristic' => 'Analyzing the address (structure, protocol, risky patterns)',
            'step_gsb' => 'Checking Google Safe Browsing (malware, phishing, unwanted software)',
            'step_vt' => 'Scanning with VirusTotal (70+ security engines)',
            'pending' => 'Analysis in progress…',
            'h_ok' => 'No suspicious pattern in the address', 'h_threat' => 'Dangerous protocol: {0}', 'h_warn' => '{list}',
            'note_login' => 'the address contains a login (may disguise the real site)',
            'note_ip' => 'the site is an IP address, not a domain name',
            'note_punycode' => 'the domain uses lookalike (punycode) characters',
            'note_download' => 'the link downloads a program file',
            'gsb_unreachable' => 'Google Safe Browsing could not be reached', 'gsb_http' => 'Google Safe Browsing error (HTTP {0})',
            'gsb_threat' => 'Flagged by Google Safe Browsing: {list}', 'gsb_ok' => 'Not listed by Google Safe Browsing',
            'tt_malware' => 'malware', 'tt_phishing' => 'phishing', 'tt_unwanted' => 'unwanted software', 'tt_harmful' => 'harmful application',
            'vt_threat' => 'VirusTotal: {0} of {1} engines flag this URL as malicious',
            'vt_warn' => 'VirusTotal: {0} malicious and {1} suspicious detection(s) out of {2} engines',
            'vt_ok' => 'VirusTotal: no engine flags this URL ({0} engines)',
            'vt_unreachable' => 'VirusTotal could not be reached', 'vt_quota' => 'VirusTotal quota reached, try again later',
            'vt_badkey' => 'VirusTotal rejected the API key', 'vt_failed' => 'VirusTotal could not analyze this URL',
            'bad_analysis' => 'Invalid analysis', 'unknown_link' => 'Unknown link', 'unknown_check' => 'Unknown check',
            'no_key' => 'No API key saved yet', 'key_ok' => 'API key accepted',
        ],
        'vi' => [
            'page_title' => 'Đang quét liên kết', 'title_scanning' => 'Đang quét liên kết…',
            'text_scanning' => 'Chúng tôi đang kiểm tra liên kết này để phát hiện mã độc và lừa đảo trước khi bạn tiếp tục.',
            'destination' => 'Đích đến',
            'safe' => 'Không phát hiện mối đe dọa', 'safe_text' => 'Liên kết này có vẻ an toàn. Bạn có thể tiếp tục.',
            'caution' => 'Hãy thận trọng khi tiếp tục', 'caution_text' => 'Chưa xác nhận mối đe dọa nào, nhưng một số bước kiểm tra có lưu ý hoặc không hoàn tất.',
            'threat' => 'Đã chặn liên kết nguy hiểm', 'threat_text' => 'Liên kết này bị gắn cờ độc hại. Không nên tiếp tục.',
            'running' => 'Đang chạy…', 'timeout' => 'Phân tích mất quá nhiều thời gian', 'failed' => 'Kiểm tra thất bại',
            'continue' => 'Tiếp tục đến trang web', 'back' => 'Quay lại',
            'risk' => 'Tôi hiểu rủi ro', 'force' => 'Vẫn tiếp tục (không khuyến nghị)',
            'noscript' => 'Cần bật JavaScript để quét liên kết này.', 'noscript_go' => 'Tiếp tục không quét',
            'protected' => 'Được bảo vệ bởi {0}', 'and' => 'và', 'language' => 'Ngôn ngữ',
            'step_heuristic' => 'Phân tích địa chỉ (cấu trúc, giao thức, mẫu đáng ngờ)',
            'step_gsb' => 'Kiểm tra Google Safe Browsing (mã độc, lừa đảo, phần mềm không mong muốn)',
            'step_vt' => 'Quét bằng VirusTotal (hơn 70 bộ quét bảo mật)',
            'pending' => 'Đang phân tích…',
            'h_ok' => 'Địa chỉ không có dấu hiệu đáng ngờ', 'h_threat' => 'Giao thức nguy hiểm: {0}', 'h_warn' => '{list}',
            'note_login' => 'địa chỉ chứa thông tin đăng nhập (có thể che giấu trang thật)',
            'note_ip' => 'trang web là địa chỉ IP, không phải tên miền',
            'note_punycode' => 'tên miền dùng ký tự giả mạo giống chữ thật (punycode)',
            'note_download' => 'liên kết tải về một tệp chương trình',
            'gsb_unreachable' => 'Không kết nối được Google Safe Browsing', 'gsb_http' => 'Google Safe Browsing báo lỗi (HTTP {0})',
            'gsb_threat' => 'Google Safe Browsing đã gắn cờ: {list}', 'gsb_ok' => 'Không có trong danh sách cảnh báo của Google Safe Browsing',
            'tt_malware' => 'mã độc', 'tt_phishing' => 'lừa đảo (phishing)', 'tt_unwanted' => 'phần mềm không mong muốn', 'tt_harmful' => 'ứng dụng có hại',
            'vt_threat' => 'VirusTotal: {0}/{1} bộ quét đánh dấu URL này là độc hại',
            'vt_warn' => 'VirusTotal: {0} phát hiện độc hại và {1} đáng ngờ trên {2} bộ quét',
            'vt_ok' => 'VirusTotal: không bộ quét nào đánh dấu URL này ({0} bộ quét)',
            'vt_unreachable' => 'Không kết nối được VirusTotal', 'vt_quota' => 'VirusTotal đã hết hạn mức, hãy thử lại sau',
            'vt_badkey' => 'VirusTotal từ chối API key', 'vt_failed' => 'VirusTotal không phân tích được URL này',
            'bad_analysis' => 'Phiên phân tích không hợp lệ', 'unknown_link' => 'Liên kết không tồn tại', 'unknown_check' => 'Bước kiểm tra không hợp lệ',
            'no_key' => 'Chưa lưu API key', 'key_ok' => 'API key hợp lệ',
        ],
    ];
    return $dict;
}

/**
 * Language of the scan page: ?lang=vi|en, then cookie "yourls_scan_lang", then browser language, then English.
 * Can be forced for the current request with $set.
 *
 * @param  string|null $set
 * @return string  'en' or 'vi'
 */
function yourls_scan_lang( $set = null ):string {
    static $lang = null;
    if( $set !== null ) {
        $lang = in_array( $set, [ 'en', 'vi' ], true ) ? $set : 'en';
    }
    if( $lang === null ) {
        $lang = 'en';
        $wanted = $_GET['lang'] ?? ( $_COOKIE['yourls_scan_lang'] ?? '' );
        if( in_array( $wanted, [ 'en', 'vi' ], true ) ) {
            $lang = $wanted;
        } elseif( preg_match( '/^\s*vi\b/i', (string) ( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '' ) ) ) {
            $lang = 'vi';
        }
    }
    return $lang;
}

/**
 * Translate a scan text
 *
 * @param  string      $key
 * @param  array       $args  Values for {0}, {1}, ...
 * @param  string|null $lang  Defaults to the current scan language
 * @return string
 */
function yourls_scan_t( $key, array $args = [], $lang = null ):string {
    $dict = yourls_scan_dictionary();
    $lang = $lang ?? yourls_scan_lang();
    $text = $dict[ $lang ][ $key ] ?? ( $dict['en'][ $key ] ?? $key );
    foreach( array_values( $args ) as $i => $value ) {
        $text = str_replace( '{' . $i . '}', (string) $value, $text );
    }
    return $text;
}

/**
 * Text of a check result, in the current (or given) language. A result carries a message key, scalar args, and
 * optionally a list of codes translated with a key prefix: [ 'prefix' => 'note_', 'codes' => [ 'ip', 'login' ], 'sep' => '; ' ].
 * Same algorithm as render() in js/scan.js.
 */
function yourls_scan_message( array $result, $lang = null ):string {
    $text = yourls_scan_t( $result['key'], $result['args'] ?? [], $lang );
    if( !empty( $result['list'] ) ) {
        $items = array_map( function( $code ) use ( $result, $lang ) {
            return yourls_scan_t( $result['list']['prefix'] . $code, [], $lang );
        }, $result['list']['codes'] );
        $joined = implode( $result['list']['sep'] ?? ', ', $items );
        if( !empty( $result['list']['ucfirst'] ) ) {
            $joined = mb_strtoupper( mb_substr( $joined, 0, 1 ) ) . mb_substr( $joined, 1 );
        }
        $text = str_replace( '{list}', $joined, $text );
    }
    return $text;
}

/* ------------------------------------------------------------------ cache */

/**
 * Create the cache table if needed (once per request). Never throws.
 *
 * @return void
 */
function yourls_scan_ensure_table() {
    static $done = false;
    if( $done ) {
        return;
    }
    $done = true;
    try {
        yourls_get_db( 'write-scan_ensure_table' )->perform(
            'CREATE TABLE IF NOT EXISTS `' . YOURLS_DB_TABLE_SCAN . '` ('.
            '`cache_key` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,'.
            '`result` text COLLATE utf8mb4_unicode_ci NOT NULL,'.
            '`expires` int(10) unsigned NOT NULL,'.
            'PRIMARY KEY (`cache_key`)'.
            ') DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;'
        );
    } catch( \Throwable $e ) {
        // cache is optional
    }
}

/**
 * @param  string $url
 * @param  string $step
 * @return string
 */
function yourls_scan_cache_key( $url, $step ):string {
    return sha1( $url ) . '-' . preg_replace( '/[^a-z_]/', '', $step );
}

/**
 * @return array|null  Cached check result, or null
 */
function yourls_scan_cache_get( $url, $step ) {
    yourls_scan_ensure_table();
    try {
        $row = yourls_get_db( 'read-scan_cache_get' )->fetchObject(
            'SELECT `result` FROM `' . YOURLS_DB_TABLE_SCAN . '` WHERE `cache_key` = :k AND `expires` > :now',
            [ 'k' => yourls_scan_cache_key( $url, $step ), 'now' => time() ]
        );
        if( $row ) {
            $result = json_decode( $row->result, true );
            if( is_array( $result ) && isset( $result['key'] ) ) {
                $result['cached']  = true;
                $result['message'] = yourls_scan_message( $result );
                return $result;
            }
        }
    } catch( \Throwable $e ) {
    }
    return null;
}

/**
 * Cache a final check result: safe results for 24h, threats for 6h. Errors and pending states are not cached.
 */
function yourls_scan_cache_set( $url, $step, array $result ) {
    $ttl = [ 'ok' => 86400, 'warn' => 86400, 'threat' => 21600 ][ $result['status'] ] ?? 0;
    if( !$ttl ) {
        return;
    }
    yourls_scan_ensure_table();
    try {
        yourls_get_db( 'write-scan_cache_set' )->perform(
            'REPLACE INTO `' . YOURLS_DB_TABLE_SCAN . '` (`cache_key`, `result`, `expires`) VALUES (:k, :r, :e)',
            [ 'k' => yourls_scan_cache_key( $url, $step ), 'r' => json_encode( array_diff_key( $result, [ 'message' => 1 ] ) ), 'e' => time() + $ttl ]
        );
        // Opportunistic cleanup
        if( mt_rand( 1, 50 ) === 1 ) {
            yourls_get_db( 'write-scan_cache_clean' )->perform( 'DELETE FROM `' . YOURLS_DB_TABLE_SCAN . '` WHERE `expires` < :now', [ 'now' => time() ] );
        }
    } catch( \Throwable $e ) {
    }
}

/* ----------------------------------------------------------------- checks */

/**
 * Build a check result
 *
 * @param  string $status  ok | warn | threat | error | pending
 * @param  string $key     Message key in yourls_scan_dictionary()
 * @param  array  $args    Values for {0}, {1}, ...
 * @param  array  $extra   More fields (eg 'list', 'id')
 * @return array
 */
function yourls_scan_result( $status, $key, array $args = [], array $extra = [] ):array {
    $result = array_merge( [ 'status' => $status, 'key' => $key, 'args' => $args ], $extra );
    $result['message'] = yourls_scan_message( $result );
    return $result;
}

/**
 * Offline checks on the URL itself
 */
function yourls_scan_heuristic( $url ):array {
    $scheme = strtolower( (string) parse_url( $url, PHP_URL_SCHEME ) );
    $host   = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );
    $path   = strtolower( (string) parse_url( $url, PHP_URL_PATH ) );

    if( in_array( $scheme, [ 'javascript', 'data', 'vbscript', 'file' ], true ) ) {
        return yourls_scan_result( 'threat', 'h_threat', [ $scheme . ':' ] );
    }

    $notes = [];
    if( parse_url( $url, PHP_URL_USER ) !== null ) {
        $notes[] = 'login';
    }
    if( filter_var( $host, FILTER_VALIDATE_IP ) || preg_match( '/^\d+$/', $host ) ) {
        $notes[] = 'ip';
    }
    if( strpos( $host, 'xn--' ) !== false ) {
        $notes[] = 'punycode';
    }
    if( preg_match( '/\.(exe|scr|msi|apk|bat|cmd|vbs|ps1|jar|dmg|pkg|iso)$/', $path ) ) {
        $notes[] = 'download';
    }
    $notes = yourls_apply_filter( 'scan_heuristic_notes', $notes, $url );

    if( $notes ) {
        return yourls_scan_result( 'warn', 'h_warn', [], [ 'list' => [ 'prefix' => 'note_', 'codes' => $notes, 'sep' => '; ', 'ucfirst' => true ] ] );
    }
    return yourls_scan_result( 'ok', 'h_ok' );
}

/**
 * Google Safe Browsing (Lookup API v4)
 */
function yourls_scan_gsb( $url ):array {
    $body = json_encode( [
        'client'     => [ 'clientId' => 'yourls', 'clientVersion' => YOURLS_VERSION ],
        'threatInfo' => [
            'threatTypes'      => [ 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION' ],
            'platformTypes'    => [ 'ANY_PLATFORM' ],
            'threatEntryTypes' => [ 'URL' ],
            'threatEntries'    => [ [ 'url' => $url ] ],
        ],
    ] );
    $response = yourls_http_post(
        'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode( yourls_scan_key( 'gsb' ) ),
        [ 'Content-Type' => 'application/json' ],
        $body,
        [ 'timeout' => 8 ]
    );
    if( !is_object( $response ) || !isset( $response->status_code ) ) {
        return yourls_scan_result( 'error', 'gsb_unreachable' );
    }
    $json = json_decode( (string) $response->body, true );
    if( $response->status_code !== 200 || !is_array( $json ) ) {
        return yourls_scan_result( 'error', 'gsb_http', [ (int) $response->status_code ] );
    }
    if( !empty( $json['matches'] ) ) {
        $codes = [ 'MALWARE' => 'malware', 'SOCIAL_ENGINEERING' => 'phishing', 'UNWANTED_SOFTWARE' => 'unwanted', 'POTENTIALLY_HARMFUL_APPLICATION' => 'harmful' ];
        $types = array_unique( array_column( $json['matches'], 'threatType' ) );
        $found = array_values( array_unique( array_map( function( $t ) use ( $codes ) { return $codes[ $t ] ?? 'malware'; }, $types ) ) );
        return yourls_scan_result( 'threat', 'gsb_threat', [], [ 'list' => [ 'prefix' => 'tt_', 'codes' => $found, 'sep' => ', ' ] ] );
    }
    return yourls_scan_result( 'ok', 'gsb_ok' );
}

/**
 * Interpret VirusTotal analysis stats
 */
function yourls_scan_vt_verdict( array $stats ):array {
    $malicious  = (int) ( $stats['malicious'] ?? 0 );
    $suspicious = (int) ( $stats['suspicious'] ?? 0 );
    $total      = array_sum( array_map( 'intval', $stats ) );
    if( $malicious >= 2 ) {
        return yourls_scan_result( 'threat', 'vt_threat', [ $malicious, $total ] );
    }
    if( $malicious === 1 || $suspicious >= 2 ) {
        return yourls_scan_result( 'warn', 'vt_warn', [ $malicious, $suspicious, $total ] );
    }
    return yourls_scan_result( 'ok', 'vt_ok', [ $total ] );
}

/**
 * @param  string $method  GET | POST
 * @return array|false     [ status_code, json ] or false when unreachable
 */
function yourls_scan_vt_call( $method, $path, $data = [] ) {
    $url     = 'https://www.virustotal.com/api/v3/' . $path;
    $headers = [ 'x-apikey' => yourls_scan_key( 'vt' ), 'accept' => 'application/json' ];
    $options = [ 'timeout' => 8 ];
    $response = ( $method === 'POST' ) ? yourls_http_post( $url, $headers, $data, $options ) : yourls_http_get( $url, $headers, $data, $options );
    if( !is_object( $response ) || !isset( $response->status_code ) ) {
        return false;
    }
    return [ (int) $response->status_code, json_decode( (string) $response->body, true ) ];
}

/**
 * VirusTotal: reuse a recent report if one exists, otherwise submit the URL (state "pending" + analysis id to poll)
 */
function yourls_scan_vt( $url ):array {
    // 1. Existing report (instant)
    $id   = rtrim( strtr( base64_encode( $url ), '+/', '-_' ), '=' );
    $call = yourls_scan_vt_call( 'GET', 'urls/' . $id );
    if( $call === false ) {
        return yourls_scan_result( 'error', 'vt_unreachable' );
    }
    if( $call[0] === 200 && !empty( $call[1]['data']['attributes']['last_analysis_stats'] ) ) {
        $stats = $call[1]['data']['attributes']['last_analysis_stats'];
        if( array_sum( array_map( 'intval', $stats ) ) > 0 ) {
            return yourls_scan_vt_verdict( $stats );
        }
    }
    if( $call[0] === 429 ) {
        return yourls_scan_result( 'error', 'vt_quota' );
    }
    if( $call[0] === 401 || $call[0] === 403 ) {
        return yourls_scan_result( 'error', 'vt_badkey' );
    }

    // 2. Submit for analysis
    $call = yourls_scan_vt_call( 'POST', 'urls', [ 'url' => $url ] );
    if( $call === false || $call[0] !== 200 || empty( $call[1]['data']['id'] ) ) {
        return yourls_scan_result( 'error', $call && $call[0] === 429 ? 'vt_quota' : 'vt_failed' );
    }
    return yourls_scan_result( 'pending', 'pending', [], [ 'id' => $call[1]['data']['id'] ] );
}

/**
 * VirusTotal: poll an analysis started by yourls_scan_vt()
 */
function yourls_scan_vt_poll( $analysis_id ):array {
    if( !preg_match( '/^[A-Za-z0-9=_-]{10,200}$/', (string) $analysis_id ) ) {
        return yourls_scan_result( 'error', 'bad_analysis' );
    }
    $call = yourls_scan_vt_call( 'GET', 'analyses/' . $analysis_id );
    if( $call === false || $call[0] !== 200 ) {
        return yourls_scan_result( 'error', 'vt_unreachable' );
    }
    $attr = $call[1]['data']['attributes'] ?? [];
    if( ( $attr['status'] ?? '' ) !== 'completed' ) {
        return yourls_scan_result( 'pending', 'pending', [], [ 'id' => $analysis_id ] );
    }
    return yourls_scan_vt_verdict( $attr['stats'] ?? [] );
}

/**
 * Run one scan step for a short URL. The URL always comes from the database, never from the request.
 *
 * @param  string $keyword
 * @param  string $step     heuristic | gsb | vt | vt_poll
 * @param  string $arg      Analysis id for vt_poll
 * @return array            [ status, message, ... ]
 */
function yourls_scan_step( $keyword, $step, $arg = '' ):array {
    $url = yourls_get_keyword_longurl( $keyword );
    if( !$url ) {
        return yourls_scan_result( 'error', 'unknown_link' );
    }
    $checks = yourls_scan_checks();
    $key    = ( $step === 'vt_poll' ) ? 'vt' : $step;
    if( !isset( $checks[ $key ] ) ) {
        return yourls_scan_result( 'error', 'unknown_check' );
    }

    if( $step !== 'vt_poll' && ( $cached = yourls_scan_cache_get( $url, $step ) ) ) {
        return $cached;
    }

    switch( $step ) {
        case 'heuristic': $result = yourls_scan_heuristic( $url ); break;
        case 'gsb':       $result = yourls_scan_gsb( $url );       break;
        case 'vt':        $result = yourls_scan_vt( $url );        break;
        case 'vt_poll':   $result = yourls_scan_vt_poll( $arg );   break;
        default:          return yourls_scan_result( 'error', 'unknown_check' );
    }
    $result = yourls_apply_filter( 'scan_step_result', $result, $step, $url );

    if( $result['status'] !== 'pending' ) {
        yourls_scan_cache_set( $url, $key, $result );
    }
    return $result;
}

/* ------------------------------------------------------------ interstitial */

/**
 * Output the scan page for a short URL: progress of the checks, then a Continue button if the URL is safe.
 * The click is counted when the page is displayed. Visitors can switch between English and Vietnamese (no reload).
 *
 * @param  string $keyword
 * @param  string $url      Long URL
 * @return void
 */
function yourls_scan_page( $keyword, $url ) {
    yourls_do_action( 'scan_page', $url, $keyword );

    // Same bookkeeping as yourls_redirect_shorturl(), without the redirect
    yourls_update_clicks( $keyword );
    yourls_log_redirect( $keyword );
    yourls_robots_tag_header();
    yourls_status_header( 200 );
    yourls_content_type_header( 'text/html' );
    header( 'Cache-Control: no-store' );
    header( 'Vary: Accept-Language, Cookie' );

    $lang   = yourls_scan_lang();
    $checks = yourls_scan_checks();
    $steps  = array_keys( $checks );
    $services = [];
    if( yourls_scan_provider_enabled( 'gsb' ) ) {
        $services[] = [ 'name' => 'Google Safe Browsing', 'url' => 'https://safebrowsing.google.com/' ];
    }
    if( yourls_scan_provider_enabled( 'vt' ) ) {
        $services[] = [ 'name' => 'VirusTotal', 'url' => 'https://www.virustotal.com/' ];
    }
    if( !$services ) {
        $services[] = [ 'name' => 'YOURLS', 'url' => 'http://yourls.org/' ];
    }
    $config = [
        'endpoint' => yourls_site_url( false ) . '/yourls-scan.php',
        'keyword'  => $keyword,
        'steps'    => $steps,
        'lang'     => $lang,
        'dict'     => yourls_scan_dictionary(),
        'services' => $services,
    ];
    $host = (string) parse_url( $url, PHP_URL_HOST );
    $t = function( $key ) use ( $lang ) { return yourls_esc_html( yourls_scan_t( $key, [], $lang ) ); };
    ?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex, nofollow" />
    <title><?php echo $t( 'page_title' ); ?> &mdash; <?php echo yourls_esc_html( $host ); ?></title>
    <link rel="stylesheet" href="<?php echo yourls_asset_url( 'css/scan.css' ); ?>" type="text/css" />
    <script src="<?php echo yourls_asset_url( 'js/scan.js' ); ?>" defer></script>
</head>
<body>
<main class="scan-card" id="scan" data-config="<?php echo yourls_esc_attr( json_encode( $config ) ); ?>">
    <div class="scan-lang" role="group" aria-label="<?php echo $t( 'language' ); ?>">
        <button type="button" data-lang="en" aria-pressed="<?php echo $lang === 'en' ? 'true' : 'false'; ?>">EN</button>
        <button type="button" data-lang="vi" aria-pressed="<?php echo $lang === 'vi' ? 'true' : 'false'; ?>">VI</button>
    </div>
    <div class="scan-status" id="scan-status" aria-live="polite">
        <div class="scan-icon" id="scan-icon"><span class="spinner"></span></div>
        <h1 id="scan-title" data-i18n="title_scanning"><?php echo $t( 'title_scanning' ); ?></h1>
        <p id="scan-text" data-i18n="text_scanning"><?php echo $t( 'text_scanning' ); ?></p>
    </div>
    <div class="scan-target" title="<?php echo yourls_esc_attr( $url ); ?>"><span data-i18n="destination"><?php echo $t( 'destination' ); ?></span><strong><?php echo yourls_esc_html( yourls_trim_long_string( $url, 70 ) ); ?></strong></div>
    <div class="scan-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="scan-bar" id="scan-bar"></div></div>
    <ul class="scan-steps" id="scan-steps">
        <?php foreach( $steps as $id ) { ?>
        <li data-step="<?php echo yourls_esc_attr( $id ); ?>" class="pending"><span class="dot"></span><span class="label" data-i18n="step_<?php echo yourls_esc_attr( $id ); ?>"><?php echo $t( 'step_' . $id ); ?></span><span class="note"></span></li>
        <?php } ?>
    </ul>
    <div class="scan-actions" id="scan-actions" hidden>
        <a class="btn primary" id="scan-continue" href="<?php echo yourls_esc_url( $url ); ?>" rel="noopener noreferrer nofollow"><span data-i18n="continue"><?php echo $t( 'continue' ); ?></span> &rarr;</a>
        <a class="btn" id="scan-back" href="javascript:history.back()" data-i18n="back"><?php echo $t( 'back' ); ?></a>
    </div>
    <details class="scan-force" id="scan-force" hidden>
        <summary data-i18n="risk"><?php echo $t( 'risk' ); ?></summary>
        <a href="<?php echo yourls_esc_url( $url ); ?>" rel="noopener noreferrer nofollow" data-i18n="force"><?php echo $t( 'force' ); ?></a>
    </details>
    <noscript>
        <p class="scan-noscript"><?php echo $t( 'noscript' ); ?> <a href="<?php echo yourls_esc_url( $url ); ?>" rel="noopener noreferrer nofollow"><?php echo $t( 'noscript_go' ); ?></a></p>
    </noscript>
    <p class="scan-foot" id="scan-foot"><?php echo yourls_scan_footer_text( $lang ); ?></p>
</main>
</body>
</html>
    <?php
}

// Admin menu entry
yourls_add_filter( 'admin_links', function( $links ) {
    if( yourls_is_admin() ) {
        $links['scan_settings'] = [
            'url'    => yourls_admin_url( 'scan-settings.php' ),
            'anchor' => yourls__( 'Scan settings' ),
        ];
    }
    return $links;
} );

/**
 * Text shown at the bottom of the scan page, naming the services actually used
 *
 * @param  string|null $lang
 * @return string  HTML
 */
function yourls_scan_footer_text( $lang = null ):string {
    $names = [];
    if( yourls_scan_provider_enabled( 'gsb' ) ) {
        $names[] = '<a href="https://safebrowsing.google.com/" target="_blank" rel="noopener">Google Safe Browsing</a>';
    }
    if( yourls_scan_provider_enabled( 'vt' ) ) {
        $names[] = '<a href="https://www.virustotal.com/" target="_blank" rel="noopener">VirusTotal</a>';
    }
    if( !$names ) {
        $names[] = '<a href="http://yourls.org/" target="_blank" rel="noopener">YOURLS</a>';
    }
    return yourls_scan_t( 'protected', [ implode( ' ' . yourls_scan_t( 'and', [], $lang ) . ' ', $names ) ], $lang );
}
