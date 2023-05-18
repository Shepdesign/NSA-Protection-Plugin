<?php
/**
 * Plugin Name: NSA Protection Plugin
 * Description: Enhances the security and privacy of your WordPress website.
 * Version: 1.0
 * Author: SHEPDESIGN, LLC
 */

defined( 'ABSPATH' ) || exit;

// Disable file editing from the WordPress admin panel
define( 'DISALLOW_FILE_EDIT', true );

// Remove sensitive information from HTTP headers
function remove_sensitive_headers() {
    // Remove X-Pingback header
    remove_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
    remove_action( 'template_redirect', 'wp_shortlink_header', 11, 0 );

    // Remove X-Powered-By header
    header_remove( 'X-Powered-By' );
}
add_action( 'after_setup_theme', 'remove_sensitive_headers' );

// Implement security headers
function implement_security_headers() {
    // Enable Content Security Policy (CSP)
    $csp_directives = array(
        "default-src 'none';",
        "script-src 'self';",
        "style-src 'self';",
        "img-src 'self';",
        "font-src 'self';",
        "connect-src 'self';",
        "media-src 'self';",
        "form-action 'self';",
        "frame-ancestors 'none';",
        "base-uri 'none';",
        "object-src 'none';",
        "manifest-src 'self';",
        "block-all-mixed-content;",
        "upgrade-insecure-requests;",
    );
    header( "Content-Security-Policy: " . implode( ' ', $csp_directives ) );

    // Enable HTTP Strict Transport Security (HSTS)
    header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' );

    // Enable X-Frame-Options
    header( 'X-Frame-Options: DENY' );

    // Enable X-XSS-Protection
    header( 'X-XSS-Protection: 1; mode=block' );

    // Enable X-Content-Type-Options
    header( 'X-Content-Type-Options: nosniff' );

    // Enable Referrer-Policy
    header( 'Referrer-Policy: no-referrer' );
}
add_action( 'send_headers', 'implement_security_headers' );

// Prevent unauthorized access to important files
function prevent_unauthorized_file_access() {
    // Prevent access to wp-config.php file
    if ( $_SERVER['REQUEST_URI'] == '/wp-config.php' ) {
        die( 'Access denied.' );
    }

    // Prevent access to .htaccess file
    if ( basename( $_SERVER['REQUEST_URI'] ) == '.htaccess' ) {
        die( 'Access denied.' );
    }
}
add_action( 'init', 'prevent_unauthorized_file_access' );

// Remove WordPress version number from the website's header
function remove_wp_version_number() {
    return '';
}
add_filter( 'the_generator', 'remove_wp_version_number' );

// Disable XML-RPC
add_filter( 'xmlrpc_enabled', '__return_false' );

// Disable REST API if not used
add_filter( 'rest_enabled', '__return_false' );
add_filter( 'rest_jsonp_enabled', '__return_false' );

// Disable pingbacks and trackbacks
add_filter( 'xmlrpc_methods', function( $methods ) {
    unset( $methods['pingback.ping'] );
    unset( $methods['pingback.extensions.getPingbacks'] );
    return $methods;
} );
add_filter( 'wp_headers', function( $headers ) {
    unset( $headers['X-Pingback'] );
    return $headers;
} );

// Disable user enumeration
if ( ! is_admin() ) {
    add_filter( 'redirect_canonical', 'custom_disable_redirect_canonical' );
    function custom_disable_redirect_canonical( $redirect_url ) {
        if ( is_404() ) {
            return false;
        }
        return $redirect_url;
    }

    add_action( 'template_redirect', 'custom_redirect_to_404' );
    function custom_redirect_to_404() {
        global $wp_query;
        if ( is_author() || is_date() || is_attachment() || is_comments_popup() ) {
            $wp_query->set_404();
            status_header( 404 );
            nocache_headers();
        }
    }

    add_filter( 'author_rewrite_rules', '__return_empty_array' );
}

// Disable plugin and theme file editors for non-admins
if ( ! current_user_can( 'administrator' ) ) {
    define( 'DISALLOW_FILE_EDIT', true );
}
