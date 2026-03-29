<?php
/**
 * ES Football Bypass - Uninstall
 *
 * Limpia opciones, transients y archivos de log al desinstalar el plugin.
 *
 * @package ES_Football_Bypass
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Eliminar opciones del plugin.
delete_option( 'cfbcolorvivo_settings' );
delete_option( 'cfbcolorvivo_settings_last_trace' );

// Eliminar transients conocidos.
delete_transient( 'cfbcolorvivo_settings_notice_ok' );
delete_transient( 'cfbcolorvivo_settings_notice_err' );
delete_transient( 'cfbcolorvivo_domain_ips_cache' );
delete_transient( 'cfbcolorvivo_prune_throttle' );
delete_transient( 'cfbcolorvivo_server_outgoing_ips' );

// Inicializar WP_Filesystem.
global $wp_filesystem;
if ( ! function_exists( 'WP_Filesystem' ) ) {
	require_once ABSPATH . 'wp-admin/includes/file.php';
}
WP_Filesystem();

$cfbcolorvivo_upload_base = wp_upload_dir()['basedir'];

// Eliminar directorio principal del plugin en uploads.
$cfbcolorvivo_plugin_dir = $cfbcolorvivo_upload_base . '/es-football-bypass-for-cloudflare';
foreach ( array( $cfbcolorvivo_plugin_dir . '/logs', $cfbcolorvivo_plugin_dir ) as $cfbcolorvivo_dir ) {
	if ( is_dir( $cfbcolorvivo_dir ) ) {
		$cfbcolorvivo_files = glob( $cfbcolorvivo_dir . '/*' );
		if ( is_array( $cfbcolorvivo_files ) ) {
			foreach ( $cfbcolorvivo_files as $cfbcolorvivo_file ) {
				if ( is_file( $cfbcolorvivo_file ) ) {
					wp_delete_file( $cfbcolorvivo_file );
				}
			}
		}
		$wp_filesystem->rmdir( $cfbcolorvivo_dir );
	}
}

// Eliminar directorios legacy de versiones anteriores.
$cfbcolorvivo_legacy_dirs = array(
	$cfbcolorvivo_upload_base . '/cfbcolorvivo-logs',
	$cfbcolorvivo_upload_base . '/cfbcolorvivo',
);
foreach ( $cfbcolorvivo_legacy_dirs as $cfbcolorvivo_dir ) {
	if ( is_dir( $cfbcolorvivo_dir ) ) {
		$cfbcolorvivo_files = glob( $cfbcolorvivo_dir . '/*' );
		if ( is_array( $cfbcolorvivo_files ) ) {
			foreach ( $cfbcolorvivo_files as $cfbcolorvivo_file ) {
				if ( is_file( $cfbcolorvivo_file ) ) {
					wp_delete_file( $cfbcolorvivo_file );
				}
			}
		}
		$wp_filesystem->rmdir( $cfbcolorvivo_dir );
	}
}

// Limpiar cron.
wp_clear_scheduled_hook( 'cfbcolorvivo_check_football_status' );
