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
        'name' => 'Google Safe Browsing',
        'desc' => yourls__( 'Detects malware, phishing and unwanted software from Google\'s constantly updated lists.' ),
        'url'  => 'https://developers.google.com/safe-browsing/v4/get-started',
        'help' => yourls__( 'Free API key (Google Cloud console: enable "Safe Browsing API", then create an API key).' ),
    ],
    'vt'  => [
        'name' => 'VirusTotal',
        'desc' => yourls__( 'Asks more than 70 antivirus and URL reputation engines. Free tier: 4 requests per minute, 500 per day.' ),
        'url'  => 'https://www.virustotal.com/gui/my-apikey',
        'help' => yourls__( 'Free API key (create a free VirusTotal account, then open your profile "API key").' ),
    ],
];
$source_labels = [
    'config' => yourls__( 'Set in config.php' ),
    'saved'  => yourls__( 'Saved' ),
    ''       => yourls__( 'Not set' ),
];
?>

<main role="main" class="scan-settings">
    <h2 class="page-title"><?php yourls_e( 'Scan settings' ); ?> <small>&mdash; <?php yourls_e( 'malicious URL scan' ); ?></small></h2>
    <p class="lead"><?php yourls_e( 'Before visitors are sent to a long URL, a page shows the progress of a security scan and lets them continue only if no threat is found. Offline checks on the address always run; the services below add online reputation checks.' ); ?></p>

    <?php foreach( $errors as $e ) { echo '<p class="error">' . yourls_esc_html( $e ) . '</p>'; } ?>
    <?php foreach( $messages as $m ) { echo '<p class="success">' . yourls_esc_html( $m ) . '</p>'; } ?>

    <form method="post" action="" autocomplete="off">
        <?php yourls_nonce_field( 'scan_settings' ); ?>

        <div class="scan-card-set">
            <label class="switch-row">
                <input type="checkbox" name="scan_enabled" value="1" <?php echo yourls_scan_enabled() ? 'checked' : ''; ?> <?php echo defined( 'YOURLS_URL_SCAN' ) ? 'disabled' : ''; ?> />
                <span><strong><?php yourls_e( 'Show the scan page before redirecting' ); ?></strong>
                <?php if( defined( 'YOURLS_URL_SCAN' ) ) { ?><small><?php yourls_e( 'Fixed by YOURLS_URL_SCAN in config.php.' ); ?></small><?php } ?></span>
            </label>
        </div>

        <?php foreach( $services as $id => $svc ) {
            list( $key, $source ) = yourls_scan_key_info( $id );
            $masked = $key !== '' ? str_repeat( '•', 8 ) . substr( $key, -4 ) : '';
            ?>
        <div class="scan-card-set" id="svc-<?php echo $id; ?>">
            <div class="svc-head">
                <h3><?php echo yourls_esc_html( $svc['name'] ); ?></h3>
                <span class="badge badge-<?php echo $source === '' ? 'off' : 'on'; ?>"><?php echo yourls_esc_html( $source_labels[ $source ] ); ?></span>
            </div>
            <p class="svc-desc"><?php echo yourls_esc_html( $svc['desc'] ); ?></p>
            <label class="field-label" for="<?php echo $id; ?>_key"><?php yourls_e( 'API key' ); ?></label>
            <div class="key-row">
                <input type="password" class="text" id="<?php echo $id; ?>_key" name="<?php echo $id; ?>_key" value="" autocomplete="new-password" spellcheck="false"
                       placeholder="<?php echo $masked !== '' ? yourls_esc_attr( $masked . ' — ' . yourls__( 'leave empty to keep' ) ) : yourls_esc_attr__( 'Paste your API key' ); ?>" <?php echo $source === 'config' ? 'disabled' : ''; ?> />
                <button type="button" class="button toggle-key" data-target="<?php echo $id; ?>_key"><?php yourls_e( 'Show' ); ?></button>
                <button type="button" class="button test-key" data-service="<?php echo $id; ?>" <?php echo $key === '' ? 'disabled' : ''; ?>><?php yourls_e( 'Test saved key' ); ?></button>
            </div>
            <p class="svc-help"><?php echo yourls_esc_html( $svc['help'] ); ?> <a href="<?php echo yourls_esc_url( $svc['url'] ); ?>" target="_blank" rel="noopener"><?php yourls_e( 'Get a key' ); ?> &rarr;</a></p>
            <?php if( $source === 'saved' ) { ?>
            <label class="clear-row"><input type="checkbox" name="<?php echo $id; ?>_clear" value="1" /> <?php yourls_e( 'Remove the saved key' ); ?></label>
            <?php } ?>
            <div class="test-result" id="test-<?php echo $id; ?>" hidden></div>
        </div>
        <?php } ?>

        <p><input type="submit" class="button primary" value="<?php yourls_e( 'Save settings' ); ?>" /></p>
    </form>
    <script>var scanTestNonce = <?php echo json_encode( yourls_create_nonce( 'scan_settings' ) ); ?>;</script>
</main>

<?php yourls_html_footer(); ?>
