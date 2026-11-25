<?php
/**
 * Settings of the malicious URL scan: on/off and API keys of Google Safe Browsing and VirusTotal.
 */
define( 'YOURLS_ADMIN', true );
require_once( dirname( __DIR__ ).'/includes/load-yourls.php' );
yourls_maybe_require_auth();

$messages = [];
$errors   = [];

if( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
    yourls_verify_nonce( 'scan_settings', $_POST['nonce'] ?? '' );

    // On / off (ignored when YOURLS_URL_SCAN is set in config.php)
    if( !defined( 'YOURLS_URL_SCAN' ) ) {
        yourls_update_option( 'scan_enabled', empty( $_POST['scan_enabled'] ) ? '0' : '1' );
    }

    foreach( [ 'gsb' => 'Google Safe Browsing', 'vt' => 'VirusTotal' ] as $service => $name ) {
        $option = 'scan_' . $service . '_key';
        if( !empty( $_POST[ $service . '_clear' ] ) ) {
            yourls_delete_option( $option );
            $messages[] = yourls_s( '%s API key removed.', $name );
            continue;
        }
        $key = trim( (string) ( $_POST[ $service . '_key' ] ?? '' ) );
        if( $key === '' ) {
            continue; // empty field = keep the saved key
        }
        if( !preg_match( '/^[A-Za-z0-9_\-]{10,200}$/', $key ) ) {
            $errors[] = yourls_s( '%s API key looks invalid (letters, digits, - and _ only).', $name );
            continue;
        }
        yourls_update_option( $option, $key );
        $messages[] = yourls_s( '%s API key saved.', $name );
    }
    if( !$errors && !$messages ) {
        $messages[] = yourls__( 'Settings saved.' );
    }
}

yourls_add_action( 'html_head', function() {
    echo '<link rel="stylesheet" href="' . yourls_asset_url( 'css/scan-settings.css' ) . '" type="text/css" media="screen" />' . "\n";
    echo '<script src="' . yourls_asset_url( 'js/scan-settings.js' ) . '" type="text/javascript" defer></script>' . "\n";
} );

yourls_html_head( 'scan_settings', yourls__( 'Scan settings' ) );
yourls_html_logo();
yourls_html_menu();

$services = [
    'gsb' => [
        'name'  => 'Google Safe Browsing',
        'icon'  => 'G',
        'color' => '#4285f4',
        'desc'  => yourls__( 'Detects malware, phishing and unwanted software from Google\'s constantly updated lists.' ),
        'url'   => 'https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com',
        'note'  => yourls__( 'Free for non-commercial use. For commercial use Google asks you to use its paid Web Risk API instead.' ),
        'steps' => [
            yourls_s( 'Open the %s and sign in with a Google account. Create a project (top bar, project selector, "New project") or pick an existing one.', '<a href="https://console.cloud.google.com/" target="_blank" rel="noopener">Google Cloud console</a>' ),
            yourls_s( 'Go to <strong>APIs &amp; Services &rarr; Library</strong>, search for <strong>Safe Browsing API</strong> and click <strong>Enable</strong> (%s).', '<a href="https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com" target="_blank" rel="noopener">' . yourls__( 'direct link' ) . '</a>' ),
            yourls__( 'Go to <strong>APIs &amp; Services &rarr; Credentials</strong>, click <strong>Create credentials &rarr; API key</strong>. Copy the key shown (it looks like <code>AIza…</code>).' ),
            yourls__( 'Recommended: click <strong>Restrict key</strong>, under <em>API restrictions</em> choose <strong>Safe Browsing API</strong>, and under <em>Application restrictions</em> choose <strong>IP addresses</strong> and enter this server\'s IP address.' ),
            yourls__( 'Paste the key below, click <strong>Save settings</strong>, then <strong>Test saved key</strong>.' ),
        ],
    ],
    'vt'  => [
        'name'  => 'VirusTotal',
        'icon'  => 'VT',
        'color' => '#394eff',
        'desc'  => yourls__( 'Asks more than 70 antivirus and URL reputation engines. Free tier: 4 requests per minute, 500 per day.' ),
        'url'   => 'https://www.virustotal.com/gui/my-apikey',
        'note'  => yourls__( 'The free API is for personal, non-commercial use.' ),
        'steps' => [
            yourls_s( 'Create a free account (or sign in) at %s.', '<a href="https://www.virustotal.com/gui/join-us" target="_blank" rel="noopener">virustotal.com</a>' ),
            yourls_s( 'Open your profile menu (top right) and choose <strong>API key</strong>, or go straight to %s.', '<a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener">' . yourls__( 'this page' ) . '</a>' ),
            yourls__( 'Copy the 64-character key, paste it below, click <strong>Save settings</strong>, then <strong>Test saved key</strong>.' ),
        ],
    ],
];
$source_labels = [
    'config' => yourls__( 'Set in config.php' ),
    'saved'  => yourls__( 'Saved' ),
    ''       => yourls__( 'Not set' ),
];
$infos = [];
foreach( $services as $id => $svc ) {
    $infos[ $id ] = yourls_scan_key_info( $id );
}
$is_on = yourls_scan_enabled();
?>

<main role="main" class="scan-settings">

    <section class="ss-hero">
        <div class="ss-hero-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>
        </div>
        <div class="ss-hero-text">
            <h2><?php yourls_e( 'Scan settings' ); ?></h2>
            <p><?php yourls_e( 'Before visitors are sent to a long URL, a page shows the progress of a security scan and lets them continue only if no threat is found. Offline checks on the address always run; the services below add online reputation checks.' ); ?></p>
        </div>
        <div class="ss-chips">
            <span class="chip <?php echo $is_on ? 'on' : 'off'; ?>"><i></i><?php echo $is_on ? yourls__( 'Scan page: on' ) : yourls__( 'Scan page: off' ); ?></span>
            <span class="chip on"><i></i><?php yourls_e( 'Address checks' ); ?></span>
            <?php foreach( $services as $id => $svc ) { ?>
            <span class="chip <?php echo $infos[ $id ][1] === '' ? 'off' : 'on'; ?>"><i></i><?php echo yourls_esc_html( $svc['name'] ); ?></span>
            <?php } ?>
        </div>
    </section>

    <?php foreach( $errors as $e ) { echo '<p class="error">' . yourls_esc_html( $e ) . '</p>'; } ?>
    <?php foreach( $messages as $m ) { echo '<p class="success">' . yourls_esc_html( $m ) . '</p>'; } ?>

    <form method="post" action="" autocomplete="off">
        <?php yourls_nonce_field( 'scan_settings' ); ?>

        <div class="scan-card-set ss-toggle">
            <label class="switch">
                <input type="checkbox" name="scan_enabled" value="1" <?php echo $is_on ? 'checked' : ''; ?> <?php echo defined( 'YOURLS_URL_SCAN' ) ? 'disabled' : ''; ?> />
                <span class="slider"></span>
            </label>
            <div>
                <strong><?php yourls_e( 'Show the scan page before redirecting' ); ?></strong>
                <small><?php echo defined( 'YOURLS_URL_SCAN' ) ? yourls__( 'Fixed by YOURLS_URL_SCAN in config.php.' ) : yourls__( 'Turn off to redirect visitors immediately, without any scan.' ); ?></small>
            </div>
        </div>

        <?php foreach( $services as $id => $svc ) {
            list( $key, $source ) = $infos[ $id ];
            $masked = $key !== '' ? str_repeat( '•', 8 ) . substr( $key, -4 ) : '';
            ?>
        <section class="scan-card-set svc" id="svc-<?php echo $id; ?>">
            <div class="svc-head">
                <span class="svc-logo" style="background:<?php echo $svc['color']; ?>"><?php echo $svc['icon']; ?></span>
                <div class="svc-title">
                    <h3><?php echo yourls_esc_html( $svc['name'] ); ?></h3>
                    <p class="svc-desc"><?php echo yourls_esc_html( $svc['desc'] ); ?></p>
                </div>
                <span class="badge badge-<?php echo $source === '' ? 'off' : 'on'; ?>"><?php echo yourls_esc_html( $source_labels[ $source ] ); ?></span>
            </div>

            <label class="field-label" for="<?php echo $id; ?>_key"><?php yourls_e( 'API key' ); ?></label>
            <div class="key-row">
                <input type="password" class="text" id="<?php echo $id; ?>_key" name="<?php echo $id; ?>_key" value="" autocomplete="new-password" spellcheck="false"
                       placeholder="<?php echo $masked !== '' ? yourls_esc_attr( $masked . ' — ' . yourls__( 'leave empty to keep' ) ) : yourls_esc_attr__( 'Paste your API key' ); ?>" <?php echo $source === 'config' ? 'disabled' : ''; ?> />
                <button type="button" class="button toggle-key" data-target="<?php echo $id; ?>_key"><?php yourls_e( 'Show' ); ?></button>
                <button type="button" class="button test-key" data-service="<?php echo $id; ?>" <?php echo $key === '' ? 'disabled' : ''; ?>><?php yourls_e( 'Test saved key' ); ?></button>
            </div>
            <div class="test-result" id="test-<?php echo $id; ?>" hidden></div>
            <?php if( $source === 'saved' ) { ?>
            <label class="clear-row"><input type="checkbox" name="<?php echo $id; ?>_clear" value="1" /> <?php yourls_e( 'Remove the saved key' ); ?></label>
            <?php } ?>

            <details class="guide" <?php echo $source === '' && $id === 'gsb' ? 'open' : ''; ?>>
                <summary><?php echo yourls_s( 'How to get a %s API key', yourls_esc_html( $svc['name'] ) ); ?></summary>
                <ol class="steps">
                    <?php foreach( $svc['steps'] as $step ) { echo '<li>' . $step . '</li>'; } ?>
                </ol>
                <p class="guide-note"><?php echo yourls_esc_html( $svc['note'] ); ?></p>
                <p><a class="button primary" href="<?php echo yourls_esc_url( $svc['url'] ); ?>" target="_blank" rel="noopener"><?php yourls_e( 'Open the key page' ); ?> &rarr;</a></p>
            </details>
        </section>
        <?php } ?>

        <div class="ss-savebar">
            <span><?php yourls_e( 'Changes apply immediately to every short link.' ); ?></span>
            <input type="submit" class="button primary" value="<?php yourls_e( 'Save settings' ); ?>" />
        </div>
    </form>
    <script>var scanTestNonce = <?php echo json_encode( yourls_create_nonce( 'scan_settings' ) ); ?>;</script>
</main>

<?php yourls_html_footer(); ?>
