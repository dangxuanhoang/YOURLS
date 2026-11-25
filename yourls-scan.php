<?php
/**
 * Scan endpoint used by the scan page (js/scan.js): runs ONE check for a short URL and returns JSON.
 * The URL to scan is always read from the database from the keyword, never from the request.
 */
define( 'YOURLS_GO', true );
require_once( dirname( __FILE__ ) . '/includes/load-yourls.php' );

yourls_content_type_header( 'application/json' );
yourls_no_cache_headers();

$keyword = isset( $_GET['keyword'] ) ? yourls_sanitize_keyword( $_GET['keyword'] ) : '';
$step    = isset( $_GET['step'] ) ? (string) $_GET['step'] : '';
$arg     = isset( $_GET['id'] ) ? (string) $_GET['id'] : '';

if( $keyword === '' || !yourls_scan_enabled() ) {
    echo json_encode( [ 'status' => 'error', 'message' => '' ] );
    die();
}

echo json_encode( yourls_scan_step( $keyword, $step, $arg ) );
die();
