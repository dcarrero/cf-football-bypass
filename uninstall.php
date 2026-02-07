<?php
/**
 * CF Football Bypass - Uninstall
 *
 * Limpia opciones, transients y archivos de log al desinstalar el plugin.
 *
 * @package CF_Football_Bypass
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Eliminar opciones del plugin
delete_option('cfbcolorvivo_settings');
delete_option('cfbcolorvivo_settings_last_trace');

// Eliminar transients conocidos
delete_transient('cfbcolorvivo_settings_notice_ok');
delete_transient('cfbcolorvivo_settings_notice_err');
delete_transient('cfbcolorvivo_domain_ips_cache');
delete_transient('cfbcolorvivo_prune_throttle');
delete_transient('cfbcolorvivo_server_outgoing_ips');

// Inicializar WP_Filesystem
global $wp_filesystem;
if (!function_exists('WP_Filesystem')) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
}
WP_Filesystem();

// Eliminar directorio de logs
$cfbcolorvivo_log_dir = WP_CONTENT_DIR . '/uploads/cfbcolorvivo-logs';
if (is_dir($cfbcolorvivo_log_dir)) {
    $cfbcolorvivo_files = glob($cfbcolorvivo_log_dir . '/*');
    if (is_array($cfbcolorvivo_files)) {
        foreach ($cfbcolorvivo_files as $cfbcolorvivo_file) {
            if (is_file($cfbcolorvivo_file)) {
                wp_delete_file($cfbcolorvivo_file);
            }
        }
    }
    $wp_filesystem->rmdir($cfbcolorvivo_log_dir);
}

// Eliminar directorio de datos locales
$cfbcolorvivo_data_dir = WP_CONTENT_DIR . '/uploads/cfbcolorvivo';
if (is_dir($cfbcolorvivo_data_dir)) {
    $cfbcolorvivo_files = glob($cfbcolorvivo_data_dir . '/*');
    if (is_array($cfbcolorvivo_files)) {
        foreach ($cfbcolorvivo_files as $cfbcolorvivo_file) {
            if (is_file($cfbcolorvivo_file)) {
                wp_delete_file($cfbcolorvivo_file);
            }
        }
    }
    $wp_filesystem->rmdir($cfbcolorvivo_data_dir);
}

// Limpiar cron
wp_clear_scheduled_hook('cfbcolorvivo_check_football_status');
