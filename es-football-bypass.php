<?php
/**
 * Plugin Name: ES Football Bypass for Cloudflare
 * Plugin URI: https://github.com/dcarrero/cf-football-bypass
 * Description: Operates with Cloudflare to toggle between Proxy (ON/CDN) and DNS Only (OFF) based on IP blocks, with persistent DNS cache and AJAX actions. Separate UI: Operation and Settings.
 * Version: 2.0.2
 * Author: David Carrero Fernandez-Baillo
 * Author URI: https://carrero.es
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: es-football-bypass-for-cloudflare
 * Domain Path: /languages
 * Requires at least: 6.9
 * Requires PHP: 7.4
 * Update URI: https://wordpress.org/plugins/es-football-bypass-for-cloudflare/
 *
 * @package ES_Football_Bypass
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Otra copia del plugin (de otra carpeta) ya ha declarado la clase: se avisa y se para aquí en vez de provocar un error fatal.
// La clase vive en un archivo aparte a propósito: declarada aquí, PHP la enlaza al compilar y class_exists() siempre daría true.
if ( class_exists( 'Cfbcolorvivo_Cloudflare_Football_Bypass', false ) ) {
	$cfbcolorvivo_duplicate_notice = static function () {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		load_plugin_textdomain(
			'es-football-bypass-for-cloudflare',
			false,
			dirname( plugin_basename( __FILE__ ) ) . '/languages'
		);
		$reflection = new ReflectionClass( 'Cfbcolorvivo_Cloudflare_Football_Bypass' );
		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %s: path of the other plugin copy, relative to the plugins folder. */
					__( 'ES Football Bypass for Cloudflare: another copy of this plugin is already active in %s, so this copy is not running. Deactivate the other copy and this one will take over. If you delete the other copy from the Plugins screen, your plugin settings may be deleted too.', 'es-football-bypass-for-cloudflare' ),
					plugin_basename( $reflection->getFileName() )
				)
			)
		);
	};
	add_action( 'admin_notices', $cfbcolorvivo_duplicate_notice );
	add_action( 'network_admin_notices', $cfbcolorvivo_duplicate_notice );
	return;
}

define( 'CFBCOLORVIVO_PLUGIN_FILE', __FILE__ );

require_once __DIR__ . '/includes/class-cfbcolorvivo-cloudflare-football-bypass.php';

new Cfbcolorvivo_Cloudflare_Football_Bypass();
