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
 * List of the checks that will run, as [ id => label ]
 *
 * @return array
 */
function yourls_scan_checks():array {
    $checks = [ 'heuristic' => yourls__( 'Analyzing the address (structure, protocol, risky patterns)' ) ];
    if( yourls_scan_key( 'gsb' ) !== '' ) {
        $checks['gsb'] = yourls__( 'Checking Google Safe Browsing (malware, phishing, unwanted software)' );
    }
    if( yourls_scan_key( 'vt' ) !== '' ) {
        $checks['vt'] = yourls__( 'Scanning with VirusTotal (70+ security engines)' );
    }
    return yourls_apply_filter( 'scan_checks', $checks );
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
            if( is_array( $result ) ) {
                $result['cached'] = true;
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
            [ 'k' => yourls_scan_cache_key( $url, $step ), 'r' => json_encode( $result ), 'e' => time() + $ttl ]
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
 * @param  string $status   ok | warn | threat | error | pending
 * @param  string $message
 * @param  array  $extra
 * @return array
 */
function yourls_scan_result( $status, $message, array $extra = [] ):array {
    return array_merge( [ 'status' => $status, 'message' => $message ], $extra );
}

/**
 * Offline checks on the URL itself
 */
function yourls_scan_heuristic( $url ):array {
    $scheme = strtolower( (string) parse_url( $url, PHP_URL_SCHEME ) );
    $host   = strtolower( (string) parse_url( $url, PHP_URL_HOST ) );
    $path   = strtolower( (string) parse_url( $url, PHP_URL_PATH ) );

    if( in_array( $scheme, [ 'javascript', 'data', 'vbscript', 'file' ], true ) ) {
        return yourls_scan_result( 'threat', yourls_s( 'Dangerous protocol: %s', $scheme . ':' ) );
    }

    $notes = [];
    if( parse_url( $url, PHP_URL_USER ) !== null ) {
        $notes[] = yourls__( 'the address contains a login (may disguise the real site)' );
    }
    if( filter_var( $host, FILTER_VALIDATE_IP ) || preg_match( '/^\d+$/', $host ) ) {
        $notes[] = yourls__( 'the site is an IP address, not a domain name' );
    }
    if( strpos( $host, 'xn--' ) !== false ) {
        $notes[] = yourls__( 'the domain uses lookalike (punycode) characters' );
    }
    if( preg_match( '/\.(exe|scr|msi|apk|bat|cmd|vbs|ps1|jar|dmg|pkg|iso)$/', $path ) ) {
        $notes[] = yourls__( 'the link downloads a program file' );
    }
    $notes = yourls_apply_filter( 'scan_heuristic_notes', $notes, $url );

    if( $notes ) {
        return yourls_scan_result( 'warn', ucfirst( implode( '; ', $notes ) ) );
    }
    return yourls_scan_result( 'ok', yourls__( 'No suspicious pattern in the address' ) );
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
        return yourls_scan_result( 'error', yourls__( 'Google Safe Browsing could not be reached' ) );
    }
    $json = json_decode( (string) $response->body, true );
    if( $response->status_code !== 200 || !is_array( $json ) ) {
        return yourls_scan_result( 'error', yourls_s( 'Google Safe Browsing error (HTTP %s)', (int) $response->status_code ) );
    }
    if( !empty( $json['matches'] ) ) {
        $types = array_unique( array_column( $json['matches'], 'threatType' ) );
        $names = [
            'MALWARE'                         => yourls__( 'malware' ),
            'SOCIAL_ENGINEERING'              => yourls__( 'phishing' ),
            'UNWANTED_SOFTWARE'               => yourls__( 'unwanted software' ),
            'POTENTIALLY_HARMFUL_APPLICATION' => yourls__( 'harmful application' ),
        ];
        $labels = array_map( function( $t ) use ( $names ) { return $names[ $t ] ?? strtolower( $t ); }, $types );
        return yourls_scan_result( 'threat', yourls_s( 'Flagged by Google Safe Browsing: %s', implode( ', ', $labels ) ) );
    }
    return yourls_scan_result( 'ok', yourls__( 'Not listed by Google Safe Browsing' ) );
}

/**
 * Interpret VirusTotal analysis stats
 */
function yourls_scan_vt_verdict( array $stats ):array {
    $malicious  = (int) ( $stats['malicious'] ?? 0 );
    $suspicious = (int) ( $stats['suspicious'] ?? 0 );
    $total      = array_sum( array_map( 'intval', $stats ) );
    if( $malicious >= 2 ) {
        return yourls_scan_result( 'threat', yourls_s( 'VirusTotal: %1$s of %2$s engines flag this URL as malicious', $malicious, $total ) );
    }
    if( $malicious === 1 || $suspicious >= 2 ) {
        return yourls_scan_result( 'warn', yourls_s( 'VirusTotal: %1$s malicious and %2$s suspicious detection(s) out of %3$s engines', $malicious, $suspicious, $total ) );
    }
    return yourls_scan_result( 'ok', yourls_s( 'VirusTotal: no engine flags this URL (%s engines)', $total ) );
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
        return yourls_scan_result( 'error', yourls__( 'VirusTotal could not be reached' ) );
    }
    if( $call[0] === 200 && !empty( $call[1]['data']['attributes']['last_analysis_stats'] ) ) {
        $stats = $call[1]['data']['attributes']['last_analysis_stats'];
        if( array_sum( array_map( 'intval', $stats ) ) > 0 ) {
            return yourls_scan_vt_verdict( $stats );
        }
    }
    if( $call[0] === 429 ) {
        return yourls_scan_result( 'error', yourls__( 'VirusTotal quota reached, try again later' ) );
    }
    if( $call[0] === 401 || $call[0] === 403 ) {
        return yourls_scan_result( 'error', yourls__( 'VirusTotal rejected the API key' ) );
    }

    // 2. Submit for analysis
    $call = yourls_scan_vt_call( 'POST', 'urls', [ 'url' => $url ] );
    if( $call === false || $call[0] !== 200 || empty( $call[1]['data']['id'] ) ) {
        return yourls_scan_result( 'error', $call && $call[0] === 429 ? yourls__( 'VirusTotal quota reached, try again later' ) : yourls__( 'VirusTotal could not analyze this URL' ) );
    }
    return yourls_scan_result( 'pending', yourls__( 'Analysis in progress…' ), [ 'id' => $call[1]['data']['id'] ] );
}

/**
 * VirusTotal: poll an analysis started by yourls_scan_vt()
 */
function yourls_scan_vt_poll( $analysis_id ):array {
    if( !preg_match( '/^[A-Za-z0-9=_-]{10,200}$/', (string) $analysis_id ) ) {
        return yourls_scan_result( 'error', yourls__( 'Invalid analysis' ) );
    }
    $call = yourls_scan_vt_call( 'GET', 'analyses/' . $analysis_id );
    if( $call === false || $call[0] !== 200 ) {
        return yourls_scan_result( 'error', yourls__( 'VirusTotal could not be reached' ) );
    }
    $attr = $call[1]['data']['attributes'] ?? [];
    if( ( $attr['status'] ?? '' ) !== 'completed' ) {
        return yourls_scan_result( 'pending', yourls__( 'Analysis in progress…' ), [ 'id' => $analysis_id ] );
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
        return yourls_scan_result( 'error', yourls__( 'Unknown link' ) );
    }
    $checks = yourls_scan_checks();
    $key    = ( $step === 'vt_poll' ) ? 'vt' : $step;
    if( !isset( $checks[ $key ] ) ) {
        return yourls_scan_result( 'error', yourls__( 'Unknown check' ) );
    }

    if( $step !== 'vt_poll' && ( $cached = yourls_scan_cache_get( $url, $step ) ) ) {
        return $cached;
    }

    switch( $step ) {
        case 'heuristic': $result = yourls_scan_heuristic( $url ); break;
        case 'gsb':       $result = yourls_scan_gsb( $url );       break;
        case 'vt':        $result = yourls_scan_vt( $url );        break;
        case 'vt_poll':   $result = yourls_scan_vt_poll( $arg );   break;
        default:          return yourls_scan_result( 'error', yourls__( 'Unknown check' ) );
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
 * The click is counted when the page is displayed.
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

    $checks = yourls_scan_checks();
    $config = [
        'endpoint' => yourls_site_url( false ) . '/yourls-scan.php',
        'keyword'  => $keyword,
        'steps'    => $checks,
        'i18n'     => [
            'scanning'  => yourls__( 'Scanning the link…' ),
            'safe'      => yourls__( 'No threat found' ),
            'safeText'  => yourls__( 'This link looks safe. You can continue.' ),
            'caution'   => yourls__( 'Proceed with caution' ),
            'cautionText' => yourls__( 'No threat was confirmed, but some checks raised notes or could not complete.' ),
            'threat'    => yourls__( 'Dangerous link blocked' ),
            'threatText'=> yourls__( 'This link was flagged as malicious. Continuing is strongly discouraged.' ),
            'running'   => yourls__( 'Running…' ),
            'timeout'   => yourls__( 'Analysis is taking too long' ),
            'failed'    => yourls__( 'Check failed' ),
        ],
    ];
    $host = (string) parse_url( $url, PHP_URL_HOST );
    ?>
<!DOCTYPE html>
<html <?php yourls_html_language_attributes(); ?>>
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex, nofollow" />
    <title><?php yourls_e( 'Scanning link' ); ?> &mdash; <?php echo yourls_esc_html( $host ); ?></title>
    <link rel="stylesheet" href="<?php echo yourls_asset_url( 'css/scan.css' ); ?>" type="text/css" />
    <script src="<?php echo yourls_asset_url( 'js/scan.js' ); ?>" defer></script>
</head>
<body>
<main class="scan-card" id="scan" data-config="<?php echo yourls_esc_attr( json_encode( $config ) ); ?>">
    <div class="scan-status" id="scan-status" aria-live="polite">
        <div class="scan-icon" id="scan-icon"><span class="spinner"></span></div>
        <h1 id="scan-title"><?php yourls_e( 'Scanning the link…' ); ?></h1>
        <p id="scan-text"><?php yourls_e( 'We are checking this link for malware and phishing before you continue.' ); ?></p>
    </div>
    <div class="scan-target" title="<?php echo yourls_esc_attr( $url ); ?>"><span><?php yourls_e( 'Destination' ); ?></span><strong><?php echo yourls_esc_html( yourls_trim_long_string( $url, 70 ) ); ?></strong></div>
    <div class="scan-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="scan-bar" id="scan-bar"></div></div>
    <ul class="scan-steps" id="scan-steps">
        <?php foreach( $checks as $id => $label ) { ?>
        <li data-step="<?php echo yourls_esc_attr( $id ); ?>" class="pending"><span class="dot"></span><span class="label"><?php echo yourls_esc_html( $label ); ?></span><span class="note"></span></li>
        <?php } ?>
    </ul>
    <div class="scan-actions" id="scan-actions" hidden>
        <a class="btn primary" id="scan-continue" href="<?php echo yourls_esc_url( $url ); ?>" rel="noopener noreferrer nofollow"><?php yourls_e( 'Continue to the website' ); ?> &rarr;</a>
        <a class="btn" id="scan-back" href="javascript:history.back()"><?php yourls_e( 'Go back' ); ?></a>
    </div>
    <details class="scan-force" id="scan-force" hidden>
        <summary><?php yourls_e( 'I understand the risk' ); ?></summary>
        <a href="<?php echo yourls_esc_url( $url ); ?>" rel="noopener noreferrer nofollow"><?php yourls_e( 'Continue anyway (not recommended)' ); ?></a>
    </details>
    <noscript>
        <p class="scan-noscript"><?php yourls_e( 'JavaScript is required to scan this link.' ); ?> <a href="<?php echo yourls_esc_url( $url ); ?>" rel="noopener noreferrer nofollow"><?php yourls_e( 'Continue without scanning' ); ?></a></p>
    </noscript>
    <p class="scan-foot"><?php echo yourls_scan_footer_text(); ?></p>
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
 * @return string  HTML
 */
function yourls_scan_footer_text():string {
    $names = [];
    if( yourls_scan_key( 'gsb' ) !== '' ) {
        $names[] = '<a href="https://safebrowsing.google.com/" target="_blank" rel="noopener">Google Safe Browsing</a>';
    }
    if( yourls_scan_key( 'vt' ) !== '' ) {
        $names[] = '<a href="https://www.virustotal.com/" target="_blank" rel="noopener">VirusTotal</a>';
    }
    if( !$names ) {
        return yourls_s( 'Protected by %s', 'YOURLS' );
    }
    return yourls_s( 'Protected by %s', implode( ' ' . yourls__( 'and' ) . ' ', $names ) );
}
