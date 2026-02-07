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
$log_dir = WP_CONTENT_DIR . '/uploads/cfbcolorvivo-logs';
if (is_dir($log_dir)) {
    $files = glob($log_dir . '/*');
    if (is_array($files)) {
        foreach ($files as $file) {
            if (is_file($file)) {
                wp_delete_file($file);
            }
        }
    }
    $wp_filesystem->rmdir($log_dir);
}

// Eliminar directorio de datos locales
$data_dir = WP_CONTENT_DIR . '/uploads/cfbcolorvivo';
if (is_dir($data_dir)) {
    $files = glob($data_dir . '/*');
    if (is_array($files)) {
        foreach ($files as $file) {
            if (is_file($file)) {
                wp_delete_file($file);
            }
        }
    }
    $wp_filesystem->rmdir($data_dir);
}

// Limpiar cron
wp_clear_scheduled_hook('cfbcolorvivo_check_football_status');
