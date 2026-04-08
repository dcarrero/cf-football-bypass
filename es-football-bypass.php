<?php
/**
 * Plugin Name: ES Football Bypass for Cloudflare
 * Plugin URI: https://github.com/dcarrero/cf-football-bypass
 * Description: Operates with Cloudflare to toggle between Proxy (ON/CDN) and DNS Only (OFF) based on IP blocks, with persistent DNS cache and AJAX actions. Separate UI: Operation and Settings.
 * Version: 1.9.2
 * Author: David Carrero Fernandez-Baillo
 * Author URI: https://carrero.es
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: es-football-bypass-for-cloudflare
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.4
 *
 * @package ES_Football_Bypass
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main plugin class for ES Football Bypass.
 */
final class Cfbcolorvivo_Cloudflare_Football_Bypass {

	/**
	 * Option name for plugin settings.
	 *
	 * @var string
	 */
	private $option_name  = 'cfbcolorvivo_settings';

	/**
	 * WP-Cron hook name.
	 *
	 * @var string
	 */
	private $cron_hook    = 'cfbcolorvivo_check_football_status';

	/**
	 * Freshness window in seconds (4 hours).
	 *
	 * @var int
	 */
	private $fresh_window = 240 * 60;

	/**
	 * Full path to the log file.
	 *
	 * @var string
	 */
	private $log_file_path;

	/**
	 * Directory path for log files.
	 *
	 * @var string
	 */
	private $log_dir_path;

	/**
	 * Base upload directory for plugin data files.
	 *
	 * @var string
	 */
	private $plugin_upload_dir;

	/**
	 * Whether to suppress cron rescheduling during saves.
	 *
	 * @var bool
	 */
	private $suspend_reschedule = false;

	/** Initialize plugin hooks and paths. */
	public function __construct() {
		$upload_base              = wp_upload_dir()['basedir'];
		$this->plugin_upload_dir  = $upload_base . '/es-football-bypass-for-cloudflare';
		$this->log_dir_path       = $this->plugin_upload_dir . '/logs';
		$this->log_file_path      = $this->log_dir_path . '/cfbcolorvivo-actions.log';

		// Traducciones se cargan automáticamente desde WordPress 4.6 para plugins en wordpress.org.
		add_action( 'updated_option', array( $this, 'handle_option_updated' ), 10, 3 );

		add_action( 'admin_menu', array( $this, 'register_menus' ) );
		add_action( 'admin_init', array( $this, 'settings_init' ) );
		add_action( 'admin_notices', array( $this, 'settings_save_notices' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );

		add_action( $this->cron_hook, array( $this, 'check_football_and_manage_cloudflare' ) );
		add_filter( 'cron_schedules', array( $this, 'add_custom_cron_interval' ) );

		register_activation_hook( __FILE__, array( $this, 'activate' ) );
		register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );

		add_action( 'wp_ajax_cfbcolorvivo_test_connection', array( $this, 'ajax_test_connection' ) );
		add_action( 'wp_ajax_cfbcolorvivo_manual_check', array( $this, 'ajax_manual_check' ) );
		add_action( 'wp_ajax_cfbcolorvivo_get_status', array( $this, 'ajax_get_status' ) );
		add_action( 'wp_ajax_cfbcolorvivo_force_activate', array( $this, 'ajax_force_activate' ) );
		add_action( 'wp_ajax_cfbcolorvivo_force_deactivate', array( $this, 'ajax_force_deactivate' ) );
		add_action( 'wp_ajax_cfbcolorvivo_cron_diagnostics', array( $this, 'ajax_cron_diagnostics' ) );
		add_action( 'init', array( $this, 'maybe_process_external_cron' ) );
	}

	/* ================== Utilidades ================== */

	/**
	 * Initialize and return the WP_Filesystem instance.
	 *
	 * @return WP_Filesystem_Base|false The filesystem instance or false on failure.
	 */
	private function get_wp_filesystem() {
		global $wp_filesystem;
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			WP_Filesystem();
		}
		return $wp_filesystem;
	}

	/**
	 * Convert a UTF-8 string to ASCII, transliterating special characters.
	 *
	 * @param string $s UTF-8 string to convert.
	 * @return string ASCII-safe string.
	 */
	private function to_ascii( $s ) {
		$t = $s;
		if ( function_exists( 'iconv' ) ) {
			$x = iconv( 'UTF-8', 'ASCII//TRANSLIT//IGNORE', $s );
			if ( false !== $x && null !== $x ) {
				$t = $x;
			}
		}
		$map = array(
			'¿' => '?',
			'¡' => '!',
			'…' => '...',
			'—' => '-',
			'–' => '-',
			'•' => '*',
			'á' => 'a',
			'Á' => 'A',
			'é' => 'e',
			'É' => 'E',
			'í' => 'i',
			'Í' => 'I',
			'ó' => 'o',
			'Ó' => 'O',
			'ú' => 'u',
			'Ú' => 'U',
			'ñ' => 'n',
			'Ñ' => 'N',
			'ü' => 'u',
			'Ü' => 'U',
		);
		return strtr( $t, $map );
	}
	/**
	 * Write a debug log entry when WP_DEBUG_LOG is enabled.
	 *
	 * @param mixed $msg Message or data to log.
	 */
	private function log( $msg ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			$out = is_scalar( $msg ) ? (string) $msg : wp_json_encode( $msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging when WP_DEBUG_LOG is enabled
			error_log( '[CFB] ' . $this->to_ascii( $out ) );
		}
	}
	/**
	 * Append a line to the trace bag and write to debug log.
	 *
	 * @param array|null $bag  Trace array to append to, or null.
	 * @param string     $line Message line to trace.
	 */
	private function trace( &$bag, $line ) {
		if ( is_array( $bag ) ) {
			$bag[] = $line;  // consola bonita (UTF-8).
		}
		$this->log( $line );                   // log ASCII-safe.
	}
	/**
	 * Mask a string, keeping only leading and trailing characters visible.
	 *
	 * @param string $str   String to mask.
	 * @param int    $left  Characters to keep on left.
	 * @param int    $right Characters to keep on right.
	 * @return string Masked string.
	 */
	private function mask( $str, $left = 6, $right = 4 ) {
		$s   = (string) $str;
		$len = strlen( $s );
		if ( $len <= $left + $right ) {
			return str_repeat( '*', max( 0, $len ) );
		}
		return substr( $s, 0, $left ) . str_repeat( '*', $len - $left - $right ) . substr( $s, -$right );
	}
	/**
	 * Anonymize an IP address for GDPR-compliant logging.
	 *
	 * @param string $ip IP address to anonymize.
	 * @return string Anonymized IP address.
	 */
	private function anonymize_ip( $ip ) {
		if ( empty( $ip ) || ! is_string( $ip ) ) {
			return '';
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			if ( count( $parts ) === 4 ) {
				return $parts[0] . '.' . $parts[1] . '.xxx.xxx';
			}
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$parts = explode( ':', $ip );
			if ( count( $parts ) >= 4 ) {
				return $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':xxxx:xxxx:xxxx:xxxx:xxxx';
			}
		}
		return 'xxx.xxx.xxx.xxx';
	}
	/**
	 * Check whether the given domain is a local/development environment.
	 *
	 * @param string|null $domain Domain to check, or null for current site.
	 * @return bool True if the domain is local.
	 */
	private function is_local_domain( $domain = null ) {
		if ( null === $domain ) {
			$domain = $this->get_site_domain();
		}
		if ( empty( $domain ) ) {
			return true;
		}
		if ( filter_var( $domain, FILTER_VALIDATE_IP ) ) {
			return true;
		}
		$local = array( 'localhost', 'localhost.localdomain' );
		if ( in_array( strtolower( $domain ), $local, true ) ) {
			return true;
		}
		if ( preg_match( '/\.(local|test|ddev\.site|lndo\.site|wp\.lan)$/i', $domain ) ) {
			return true;
		}
		return false;
	}
	/** Detect the outgoing IP addresses of this server (cached 1 hour). */
	private function get_server_outgoing_ips() {
		$cache_key = 'cfbcolorvivo_server_outgoing_ips';
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$services = array(
			'https://api.ipify.org',
			'https://checkip.amazonaws.com',
			'https://icanhazip.com',
		);
		$ips      = array();
		foreach ( $services as $url ) {
			$r = wp_remote_get(
				$url,
				array(
					'timeout'   => 10,
					'sslverify' => true,
				)
			);
			if ( ! is_wp_error( $r ) && wp_remote_retrieve_response_code( $r ) === 200 ) {
				$ip = trim( wp_remote_retrieve_body( $r ) );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$ips[] = $ip;
				}
			}
		}
		$ips = array_values( array_unique( $ips ) );
		if ( ! empty( $ips ) ) {
			set_transient( $cache_key, $ips, HOUR_IN_SECONDS );
		}
		return $ips;
	}
	/**
	 * Check whether an array is associative (non-sequential keys).
	 *
	 * @param mixed $arr Value to check.
	 * @return bool True if the array has non-sequential keys.
	 */
	private function is_assoc( $arr ) {
		if ( ! is_array( $arr ) ) {
			return false;
		}
		return array_keys( $arr ) !== range( 0, count( $arr ) - 1 );
	}
	/**
	 * Normalize a bool-like value (string, int, bool) to true/false/null.
	 *
	 * @param mixed $v Value to normalize.
	 * @return bool|null Normalized boolean, or null if unrecognized.
	 */
	private function normalize_bool_like( $v ) {
		if ( is_bool( $v ) ) {
			return $v;
		}
		if ( is_int( $v ) ) {
			return 0 !== $v;
		}
		if ( is_string( $v ) ) {
			$vv = strtolower( trim( $v ) );
			if ( in_array( $vv, array( '1', 'true', 'yes', 'si', 'sí', 'on', 'blocked', 'proxy', 'cdn' ), true ) ) {
				return true;
			}
			if ( in_array( $vv, array( '0', 'false', 'no', 'off', 'unblocked' ), true ) ) {
				return false;
			}
		}
		return null;
	}
	/**
	 * Get an array value by key with case-insensitive lookup.
	 *
	 * @param array  $array Array to search in.
	 * @param string $key   Key to look up.
	 * @return mixed|null Value if found, or null.
	 */
	private function array_value_ci( $array, $key ) {
		if ( ! is_array( $array ) ) {
			return null;
		}
		if ( array_key_exists( $key, $array ) ) {
			return $array[ $key ];
		}
		$lk = strtolower( $key );
		foreach ( $array as $k => $v ) {
			if ( is_string( $k ) && strtolower( $k ) === $lk ) {
				return $v;
			}
		}
		return null;
	}
	/** Generate a random secret token for external cron authentication. */
	private function generate_cron_secret() {
		if ( function_exists( 'wp_generate_password' ) ) {
			return wp_generate_password( 32, false, false );
		}
		try {
			return bin2hex( random_bytes( 16 ) );
		} catch ( Exception $e ) {
			return md5( uniqid( '', true ) );
		}
	}

	/**
	 * Return the default settings array, optionally generating a new cron token.
	 *
	 * @param bool $force_new_token Whether to generate a fresh cron secret.
	 * @return array Default settings.
	 */
	private function get_default_settings( $force_new_token = false ) {
		$secret = $force_new_token ? $this->generate_cron_secret() : '';
		return array(
			'cloudflare_email'         => '',
			'cloudflare_api_key'       => '',
			'cloudflare_zone_id'       => '',
			'cloudflare_account_id'    => '',
			'auth_type'                => 'global',
			'check_interval'           => 15,
			'selected_records'         => array(),
			'dns_records_cache'        => array(),
			'dns_cache_last_sync'      => '',
			'last_check'               => '',
			'last_status_general'      => 'NO',
			'last_status_domain'       => 'NO',
			'last_update'              => '',
			'logging_enabled'          => 1,
			'log_retention_days'       => 30,
			'cron_secret'              => $secret,
			'bypass_active'            => 0,
			'bypass_blocked_ips'       => array(),
			'bypass_check_cooldown'    => 60,
			'bypass_last_change'       => 0,
			'force_proxy_off_override' => 0,  // NUEVO: Override para forzar OFF cuando General=SI.
		);
	}

	/** Delete the action log file. */
	private function clear_logs_file() {
		$path = $this->get_log_file_path();
		if ( file_exists( $path ) ) {
			wp_delete_file( $path );
		}
	}

	/** Create the log directory with security files if it does not exist. */
	private function ensure_log_directory() {
		$dir = $this->log_dir_path;
		if ( ! file_exists( $dir ) ) {
			if ( ! wp_mkdir_p( $dir ) ) {
				return false;
			}
		}
		$wp_fs    = $this->get_wp_filesystem();
		$htaccess = $dir . '/.htaccess';
		if ( $wp_fs && ! $wp_fs->exists( $htaccess ) ) {
			$htaccess_content = "# Deny access to log files\n<FilesMatch \"\\.(log|txt)$\">\n    Order Allow,Deny\n    Deny from all\n</FilesMatch>\n\n# Block directory listing\nOptions -Indexes\n";
			$wp_fs->put_contents( $htaccess, $htaccess_content, FS_CHMOD_FILE );
		}
		$index = $dir . '/index.php';
		if ( $wp_fs && ! $wp_fs->exists( $index ) ) {
			$wp_fs->put_contents( $index, '<?php // Silence is golden', FS_CHMOD_FILE );
		}
		return is_dir( $dir ) && wp_is_writable( $dir );
	}
	/**
	 * Reschedule cron when the check interval option changes.
	 *
	 * @param string $option Option name that was updated.
	 * @param mixed  $old    Old option value.
	 * @param mixed  $new    New option value.
	 */
	public function handle_option_updated( $option, $old, $new ) {
		if ( $option !== $this->option_name ) {
			return;
		}
		if ( $this->suspend_reschedule ) {
			return;
		}
		$old_interval = isset( $old['check_interval'] ) ? intval( $old['check_interval'] ) : null;
		$new_interval = isset( $new['check_interval'] ) ? intval( $new['check_interval'] ) : null;
		if ( $old_interval === $new_interval && wp_next_scheduled( $this->cron_hook ) ) {
			return;
		}
		$this->reschedule_cron_after_interval_change();
	}
	/**
	 * Save settings without triggering cron reschedule.
	 *
	 * @param array $settings Settings array to save.
	 * @return bool True if the option was updated.
	 */
	private function save_settings( array $settings ) {
		$this->suspend_reschedule = true;
		$result                   = update_option( $this->option_name, $settings );
		$this->suspend_reschedule = false;
		return $result;
	}
	/**
	 * Check whether a domain belongs to the given Cloudflare zone.
	 *
	 * @param string $domain Domain name to check.
	 * @param string $zone   Cloudflare zone name.
	 * @return bool True if the domain matches the zone.
	 */
	private function domain_matches_zone( $domain, $zone ) {
		$domain = strtolower( trim( (string) $domain ) );
		$zone   = strtolower( trim( (string) $zone ) );
		if ( '' === $domain || '' === $zone ) {
			return false;
		}
		if ( $domain === $zone ) {
			return true;
		}
		return substr( $domain, -strlen( '.' . $zone ) ) === '.' . $zone;
	}
	/** Return a label identifying the current WordPress user. */
	private function current_user_label() {
		if ( ! function_exists( 'wp_get_current_user' ) ) {
			return 'desconocido';
		}
		$user = wp_get_current_user();
		if ( $user && $user->exists() ) {
			return $user->user_login . ' (#' . $user->ID . ')';
		}
		return 'desconocido';
	}
	/** Return the full path to the action log file. */
	private function get_log_file_path() {
		return $this->log_file_path;
	}
	/**
	 * Append a structured event to the action log file.
	 *
	 * @param string $type    Event type identifier.
	 * @param string $message Human-readable event message.
	 * @param array  $context Optional additional context data.
	 */
	private function log_event( $type, $message, array $context = array() ) {
		$settings = $this->get_settings();
		if ( empty( $settings['logging_enabled'] ) ) {
			return;
		}

		if ( ! $this->ensure_log_directory() ) {
			$this->log( 'No se puede crear/acceder al directorio de logs' );
			return;
		}

		$path  = $this->get_log_file_path();
		$entry = array(
			'time'    => current_time( 'mysql' ),
			'type'    => (string) $type,
			'message' => $message,
		);
		if ( ! empty( $context ) ) {
			$entry['context'] = $context;
		}
		$line = wp_json_encode( $entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( false === $line ) {
			return;
		}
		$line .= "\n";

		$wp_fs = $this->get_wp_filesystem();
		if ( ! $wp_fs ) {
			return;
		}
		$existing = $wp_fs->exists( $path ) ? $wp_fs->get_contents( $path ) : '';
		$written  = $wp_fs->put_contents( $path, $existing . $line, FS_CHMOD_FILE );
		if ( false === $written ) {
			return;
		}
		$days = isset( $settings['log_retention_days'] ) ? intval( $settings['log_retention_days'] ) : 30;
		if ( false === get_transient( 'cfbcolorvivo_prune_throttle' ) ) {
			$this->prune_logs( $days );
			set_transient( 'cfbcolorvivo_prune_throttle', 1, DAY_IN_SECONDS );
		}
	}
	/**
	 * Remove log entries older than the specified number of days.
	 *
	 * @param int $days Number of days to retain.
	 */
	private function prune_logs( $days ) {
		$days = max( 1, intval( $days ) );
		$path = $this->get_log_file_path();
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return;
		}
		$lines = file( $path, FILE_IGNORE_NEW_LINES );
		if ( ! is_array( $lines ) ) {
			return;
		}
		$cutoff   = time() - ( $days * DAY_IN_SECONDS );
		$filtered = array();
		foreach ( $lines as $line ) {
			if ( '' === $line ) {
				continue;
			}
			$keep  = true;
			$entry = json_decode( $line, true );
			if ( is_array( $entry ) && ! empty( $entry['time'] ) ) {
				$ts = strtotime( $entry['time'] );
				if ( $ts && $ts < $cutoff ) {
					$keep = false;
				}
			}
			if ( $keep ) {
				$filtered[] = $line;
			}
		}
		if ( count( $filtered ) === count( $lines ) ) {
			return;
		}
		$data  = $filtered ? implode( "\n", $filtered ) . "\n" : '';
		$wp_fs = $this->get_wp_filesystem();
		if ( $wp_fs && $wp_fs->is_writable( $path ) ) {
			$wp_fs->put_contents( $path, $data, FS_CHMOD_FILE );
		}
	}
	/**
	 * Read and return log entries sorted by date, most recent first.
	 *
	 * @param int $limit Maximum number of entries to return.
	 * @return array Log entry arrays.
	 */
	private function read_log_entries( $limit = 200 ) {
		$path = $this->get_log_file_path();
		if ( ! file_exists( $path ) || ! is_readable( $path ) ) {
			return array();
		}
		$lines = file( $path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		if ( ! is_array( $lines ) ) {
			return array();
		}
		$entries = array();
		foreach ( $lines as $line ) {
			$entry = json_decode( $line, true );
			if ( ! is_array( $entry ) ) {
				$entry = array(
					'time'    => '',
					'type'    => 'info',
					'message' => $line,
				);
			}
			$entries[] = $entry;
		}
		usort(
			$entries,
			function ( $a, $b ) {
				$ta = isset( $a['time'] ) ? strtotime( (string) $a['time'] ) : 0;
				$tb = isset( $b['time'] ) ? strtotime( (string) $b['time'] ) : 0;
				if ( $ta === $tb ) {
					return 0;
				}
				return ( $ta > $tb ) ? -1 : 1;
			}
		);
		if ( $limit > 0 && count( $entries ) > $limit ) {
			$entries = array_slice( $entries, 0, $limit );
		}
		return $entries;
	}

	/** Process an external cron request if the token parameter is present. */
	public function maybe_process_external_cron() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- External cron uses token-based authentication instead of nonce
		if ( ! isset( $_GET['cfbcolorvivo_cron'] ) ) {
			return;
		}
		$s = $this->get_settings();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Token authentication for external cron
		$token = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( $_GET['token'] ) ) : '';
		if ( empty( $s['cron_secret'] ) || ! hash_equals( $s['cron_secret'], $token ) ) {
			wp_die(
				esc_html__( 'Invalid token', 'es-football-bypass-for-cloudflare' ),
				esc_html__( 'Access denied', 'es-football-bypass-for-cloudflare' ),
				array( 'response' => 403 )
			);
		}
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$this->log_event( 'external_cron', 'Cron externo disparado', array( 'ip' => $this->anonymize_ip( $remote_addr ) ) );
		$this->check_football_and_manage_cloudflare();
		wp_die( 'CFB cron OK', '', array( 'response' => 200 ) );
	}

	/* ================== Normalización / Migración ================== */

	/**
	 * Normalize the DNS records cache array structure.
	 *
	 * @param mixed $cache_in Raw DNS cache data to normalize.
	 * @return array Normalized DNS record arrays.
	 */
	private function normalize_dns_cache( $cache_in ) {
		$out = array();
		if ( is_array( $cache_in ) && $this->is_assoc( $cache_in ) ) {
			$cache_in = array_values( $cache_in );
		}
		if ( ! is_array( $cache_in ) ) {
			return $out;
		}
		foreach ( $cache_in as $r ) {
			if ( ! is_array( $r ) ) {
				continue;
			}
			$id   = isset( $r['id'] ) ? (string) $r['id'] : '';
			$name = isset( $r['name'] ) ? (string) $r['name'] : '';
			$type = isset( $r['type'] ) ? strtoupper( (string) $r['type'] ) : '';
			$cont = isset( $r['content'] ) ? (string) $r['content'] : '';
			$prox = null;
			if ( array_key_exists( 'proxied', $r ) ) {
				$prox = $this->normalize_bool_like( $r['proxied'] );
			} elseif ( array_key_exists( 'proxy', $r ) ) {
				$prox = $this->normalize_bool_like( $r['proxy'] );
			} elseif ( array_key_exists( 'cdn', $r ) ) {
				$prox = $this->normalize_bool_like( $r['cdn'] );
			}
			$ttl = isset( $r['ttl'] ) ? intval( $r['ttl'] ) : 1;
			if ( $ttl <= 0 ) {
				$ttl = 1;
			}
			if ( $id && $name && $type && $cont ) {
				$out[] = array(
					'id'      => $id,
					'name'    => $name,
					'type'    => $type,
					'content' => $cont,
					'proxied' => $prox,
					'ttl'     => $ttl,
				);
			}
		}
		return $out;
	}

	/**
	 * Normalize and migrate plugin settings, filling missing defaults.
	 *
	 * @param mixed $opt_in Raw settings from the database.
	 * @return array Tuple of (normalized settings, bool changed).
	 */
	private function normalize_settings( $opt_in ) {
		$changed  = false;
		$opt      = is_array( $opt_in ) ? $opt_in : array();
		$defaults = $this->get_default_settings();
		foreach ( $defaults as $k => $v ) {
			if ( ! array_key_exists( $k, $opt ) ) {
				$opt[ $k ] = $v;
				$changed   = true; }
		}

		$auth = in_array( $opt['auth_type'], array( 'global', 'token', 'account_token' ), true ) ? $opt['auth_type'] : 'global';
		if ( $auth !== $opt['auth_type'] ) {
			$opt['auth_type'] = 'global';
			$changed          = true; }

		$mins = max( 5, min( 60, intval( $opt['check_interval'] ) ) );
		if ( intval( $opt['check_interval'] ) !== $mins ) {
			$opt['check_interval'] = $mins;
			$changed               = true; }

		if ( is_string( $opt['selected_records'] ) ) {
			$opt['selected_records'] = array_filter( array_map( 'trim', explode( ',', $opt['selected_records'] ) ) );
			$changed                 = true; }
		if ( ! is_array( $opt['selected_records'] ) ) {
			$opt['selected_records'] = array();
			$changed                 = true; }
		$sel_norm = array();
		foreach ( $opt['selected_records'] as $rid ) {
			if ( is_scalar( $rid ) && '' !== $rid ) {
				$sel_norm[] = (string) $rid;
			}
		}
		if ( $sel_norm !== $opt['selected_records'] ) {
			$opt['selected_records'] = $sel_norm;
			$changed                 = true; }

		$norm_cache = $this->normalize_dns_cache( $opt['dns_records_cache'] );
		if ( $norm_cache !== $opt['dns_records_cache'] ) {
			$opt['dns_records_cache'] = $norm_cache;
			$changed                  = true; }

		foreach ( array( 'last_status_general', 'last_status_domain' ) as $k ) {
			$v = strtoupper( (string) $opt[ $k ] );
			if ( in_array( $v, array( 'SÍ', 'SI' ), true ) ) {
				$v = 'SI';
			} if ( ! in_array( $v, array( 'SI', 'NO' ), true ) ) {
				$v = 'NO';
			}
			if ( $v !== $opt[ $k ] ) {
				$opt[ $k ] = $v;
				$changed   = true; }
		}

		$opt['logging_enabled'] = ! empty( $opt['logging_enabled'] ) ? 1 : 0;
		$days                   = isset( $opt['log_retention_days'] ) ? intval( $opt['log_retention_days'] ) : 30;
		if ( $days < 1 ) {
			$days = 1;
		}
		if ( intval( $opt['log_retention_days'] ) !== $days ) {
			$opt['log_retention_days'] = $days;
			$changed                   = true; }
		if ( empty( $opt['cron_secret'] ) || ! is_string( $opt['cron_secret'] ) ) {
			$opt['cron_secret'] = $this->generate_cron_secret();
			$changed            = true;
		}
		$cooldown = isset( $opt['bypass_check_cooldown'] ) ? intval( $opt['bypass_check_cooldown'] ) : 60;
		if ( $cooldown < 5 ) {
			$cooldown = 5;
		}
		if ( $cooldown > 1440 ) {
			$cooldown = 1440;
		}
		if ( ! isset( $opt['bypass_check_cooldown'] ) || intval( $opt['bypass_check_cooldown'] ) !== $cooldown ) {
			$opt['bypass_check_cooldown'] = $cooldown;
			$changed                      = true;
		}
		$opt['bypass_active'] = ! empty( $opt['bypass_active'] ) ? 1 : 0;
		if ( ! isset( $opt['bypass_blocked_ips'] ) || ! is_array( $opt['bypass_blocked_ips'] ) ) {
			$opt['bypass_blocked_ips'] = array();
			$changed                   = true;
		} else {
			$normalized_ips = array();
			foreach ( $opt['bypass_blocked_ips'] as $ip ) {
				if ( is_string( $ip ) && '' !== $ip ) {
					$normalized_ips[] = $ip;
				}
			}
			if ( $normalized_ips !== $opt['bypass_blocked_ips'] ) {
				$opt['bypass_blocked_ips'] = $normalized_ips;
				$changed                   = true;
			}
		}
		$opt['bypass_last_change'] = isset( $opt['bypass_last_change'] ) ? intval( $opt['bypass_last_change'] ) : 0;

		// MODIFICACIÓN: Normalizar force_proxy_off_override.
		$opt['force_proxy_off_override'] = ! empty( $opt['force_proxy_off_override'] ) ? 1 : 0;

		return array( $opt, $changed );
	}
	/** Retrieve and normalize plugin settings from the database. */
	private function get_settings() {
		$raw                 = get_option( $this->option_name, array() );
		list($opt, $changed) = $this->normalize_settings( $raw );
		if ( $changed ) {
			$this->save_settings( $opt );
			$this->log( 'Configuracion normalizada/migrada.' ); }
		return $opt;
	}

	/* ================== Activación / Desactivación ================== */

	/** Schedule cron on plugin activation. */
	public function activate() {
		$s = $this->get_settings();
		if ( empty( $s['check_interval'] ) ) {
			$s['check_interval'] = 15;
			$this->save_settings( $s ); }
		if ( ! wp_next_scheduled( $this->cron_hook ) ) {
			$interval = max( 5, min( 60, intval( $s['check_interval'] ) ) );
			$next     = wp_next_scheduled( $this->cron_hook );
			while ( $next ) {
				wp_unschedule_event( $next, $this->cron_hook );
				$next = wp_next_scheduled( $this->cron_hook ); }
			wp_schedule_event( time() + 60, 'cf_fb_custom', $this->cron_hook );
		}
	}
	/** Unschedule cron and restore proxy on plugin deactivation. */
	public function deactivate() {
		$timestamp = wp_next_scheduled( $this->cron_hook );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, $this->cron_hook );
		}

		$opt = $this->get_settings();
		if ( ! empty( $opt['selected_records'] ) ) {
			foreach ( $opt['selected_records'] as $rid ) {
				$this->update_record_proxy_status( $rid, true ); }
			$this->log( 'Desactivado: Proxy restaurado (ON) en registros seleccionados.' );
		}
	}

	/* ================== Menús (Operación y Configuración) ================== */

	/** Register admin menu and submenu pages. */
	public function register_menus() {
		add_menu_page(
			'ES Football Bypass',
			'ES Football Bypass',
			'manage_options',
			'cfbcolorvivo-main',
			array( $this, 'render_main_page' ),
			'dashicons-shield',
			66
		);
		add_submenu_page( 'cfbcolorvivo-main', 'Operacion', 'Operación', 'manage_options', 'cfbcolorvivo-main', array( $this, 'render_main_page' ) );
		add_submenu_page( 'cfbcolorvivo-main', 'Configuracion', 'Configuración', 'manage_options', 'cfbcolorvivo-settings', array( $this, 'render_settings_page' ) );
		add_submenu_page( 'cfbcolorvivo-main', 'Registros', 'Logs', 'manage_options', 'cfbcolorvivo-logs', array( $this, 'render_logs_page' ) );
	}

	/* ================== Admin Scripts ================== */

	/**
	 * Enqueue admin scripts and localized data for plugin pages.
	 *
	 * @param string $hook Current admin page hook suffix.
	 */
	public function enqueue_admin_scripts( $hook ) {
		// Solo cargar en las páginas del plugin.
		if ( strpos( $hook, 'cfbcolorvivo-' ) === false && strpos( $hook, 'es-football-bypass-for-cloudflare' ) === false ) {
			return;
		}

		// Registrar script handle para asociar inline scripts.
		wp_register_script( 'cfbcolorvivo-admin', false, array(), '1.9.2', true );
		wp_enqueue_script( 'cfbcolorvivo-admin' );

		// Pasar datos al JavaScript.
		wp_localize_script(
			'cfbcolorvivo-admin',
			'cfbcolorvivoData',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'optionName' => $this->option_name,
			)
		);

		// Página de operación principal.
		if ( strpos( $hook, 'cfbcolorvivo-main' ) !== false ) {
			wp_add_inline_script( 'cfbcolorvivo-admin', $this->get_main_page_js() );
		}

		// Página de configuración.
		if ( strpos( $hook, 'cfbcolorvivo-settings' ) !== false ) {
			wp_add_inline_script( 'cfbcolorvivo-admin', $this->get_settings_page_js() );
			wp_add_inline_script( 'cfbcolorvivo-admin', $this->get_auth_type_js() );
		}
	}

	/** Return the inline JavaScript for the main operation page. */
	private function get_main_page_js() {
		return "(function(){
            var ajaxURL = cfbcolorvivoData.ajaxUrl;
            var optName = cfbcolorvivoData.optionName;
            var consolePre = document.getElementById('cfbcolorvivo-console-pre');
            var warn = document.getElementById('cfbcolorvivo-warn');
            function println(msg){ if (!consolePre) return; var ts=new Date().toLocaleTimeString(); consolePre.textContent += '['+ts+'] '+msg+'\\n'; }
            function clearConsole(){ if (consolePre) consolePre.textContent=''; }
            function showWait(show){ if (warn) warn.style.display = show ? '' : 'none'; }
            function selection(){
                var ids=[], wrap=document.getElementById('cfbcolorvivo-dns-list');
                if(!wrap) return ids;
                wrap.querySelectorAll('input[type=\"checkbox\"][name=\"'+optName+'[selected_records][]\"][checked], input[type=\"checkbox\"][name=\"'+optName+'[selected_records][]\"]:checked').forEach(function(cb){ ids.push(cb.value); });
                return ids;
            }
            var actionBtns = ['cfbcolorvivo-test','cfbcolorvivo-check','cfbcolorvivo-off','cfbcolorvivo-on','cfbcolorvivo-diag','cfbcolorvivo-refresh-ips'];
            function setBtnsDisabled(disabled){
                actionBtns.forEach(function(id){ var b=document.getElementById(id); if(b) b.disabled=disabled; });
            }
            function post(action, extra, cb){
                setBtnsDisabled(true);
                var data=new FormData();
                data.append('action', action);
                var testBtn=document.getElementById('cfbcolorvivo-test');
                data.append('_ajax_nonce', testBtn ? testBtn.dataset.nonce : '');
                var sel = selection();
                sel.forEach(function(id){ data.append('selected[]', id); });
                data.append(optName+'[selected_records]', JSON.stringify(sel));

                fetch(ajaxURL, { method:'POST', body:data, credentials:'same-origin', headers:{'X-Requested-With':'XMLHttpRequest'} })
                .then(async function(r){
                    var text = await r.text();
                    try { return JSON.parse(text); }
                    catch(e){ return { success:false, data:{ message:'Respuesta no JSON', raw:text, http:r.status } }; }
                })
                .then(function(res){
                    if (res && res.data && res.data.log && Array.isArray(res.data.log)) res.data.log.forEach(println);
                    if (res && res.log && Array.isArray(res.log)) res.log.forEach(println);
                    cb(res);
                })
                .catch(function(e){ println('Error de red: '+e); })
                .finally(function(){ showWait(false); setBtnsDisabled(false); });
            }
            function refreshTable(html){
                var wrap=document.getElementById('cfbcolorvivo-dns-list'); if(wrap && html) wrap.innerHTML=html;
            }
            function refreshSummary(callback){
                post('cfbcolorvivo_get_status', null, function(res){
                    if(res && res.success && res.data){
                        var d=res.data;
                        var g=document.getElementById('cfbcolorvivo-summary-general');
                        var dd=document.getElementById('cfbcolorvivo-summary-domain');
                        var i=document.getElementById('cfbcolorvivo-summary-ips');
                        var l=document.getElementById('cfbcolorvivo-summary-lastupdate');
                        if(g) g.textContent = (d.general==='SÍ')?'SI':'NO';
                        if(dd) dd.textContent = (d.domain==='SÍ')?'SI':'NO';
                        if(i) i.textContent = (d.ips && d.ips.length) ? d.ips.join(', ') : '—';
                        if(l) l.textContent = d.last_update || '—';
                    }
                    if (typeof callback === 'function') callback(res);
                });
            }

            var testBtn = document.getElementById('cfbcolorvivo-test');
            if (testBtn) {
                testBtn.addEventListener('click', function(e){
                    e.preventDefault(); clearConsole(); showWait(true);
                    println('Probar conexión y cargar DNS: iniciando…');
                    post('cfbcolorvivo_test_connection', null, function(res){
                        if (res.success){
                            refreshTable(res.data && res.data.html ? res.data.html : '');
                            println('Completado.');
                        } else {
                            if (res.data && res.data.message) println('Error: ' + res.data.message);
                            if (res.data && res.data.http) println('HTTP: ' + res.data.http);
                            if (res.data && res.data.raw) println(String(res.data.raw).substring(0,1000));
                        }
                    });
                });
            }
            var checkBtn = document.getElementById('cfbcolorvivo-check');
            if (checkBtn) {
                checkBtn.addEventListener('click', function(e){
                    e.preventDefault(); clearConsole(); showWait(true);
                    println('Comprobación manual: ejecutando…');
                    post('cfbcolorvivo_manual_check', null, function(res){
                        if (res.success){
                            var d=res.data||{};
                            println('Última comprobación: '+(d.last||'—'));
                            println('General (bloqueos IPs): '+(d.general||'—'));
                            println('Dominio bloqueado: '+(d.domain||'—'));
                            println('Última actualización (JSON de IPs): '+(d.last_update||'—'));
                            refreshSummary();
                        } else {
                            if (res.data && res.data.raw) println(String(res.data.raw).substring(0,1000));
                        }
                    });
                });
            }
            var offBtn = document.getElementById('cfbcolorvivo-off');
            if (offBtn) {
                offBtn.addEventListener('click', function(e){
                    e.preventDefault();
                    if (!confirm('¿Seguro que quieres forzar Proxy OFF (DNS Only) en los registros seleccionados?')) return;
                    clearConsole(); showWait(true);
                    println('Forzar Proxy OFF (DNS Only): iniciando…');
                    post('cfbcolorvivo_force_deactivate', null, function(res){
                        if (res.success){
                            refreshTable(res.data && res.data.html ? res.data.html : '');
                            if (res.data && res.data.message) println(res.data.message);
                            if (res.data && res.data.report) println(res.data.report);
                            refreshSummary();
                        } else {
                            if (res.data && res.data.raw) println(String(res.data.raw).substring(0,1000));
                        }
                    });
                });
            }
            var onBtn = document.getElementById('cfbcolorvivo-on');
            if (onBtn) {
                onBtn.addEventListener('click', function(e){
                    e.preventDefault();
                    if (!confirm('¿Seguro que quieres forzar Proxy ON (CDN) en los registros seleccionados?')) return;
                    clearConsole(); showWait(true);
                    println('Forzar Proxy ON (CDN): iniciando…');
                    post('cfbcolorvivo_force_activate', null, function(res){
                        if (res.success){
                            refreshTable(res.data && res.data.html ? res.data.html : '');
                            if (res.data && res.data.message) println(res.data.message);
                            if (res.data && res.data.report) println(res.data.report);
                            refreshSummary();
                        } else {
                            if (res.data && res.data.raw) println(String(res.data.raw).substring(0,1000));
                        }
                    });
                });
            }
            var diagBtn = document.getElementById('cfbcolorvivo-diag');
            if (diagBtn) {
                diagBtn.addEventListener('click', function(e){
                    e.preventDefault(); clearConsole(); showWait(true);
                    println('Diagnóstico WP-Cron…');
                    post('cfbcolorvivo_cron_diagnostics', null, function(res){
                        if (res.success && res.data && res.data.msg) println(res.data.msg);
                        else if (res.data && res.data.raw) println(String(res.data.raw).substring(0,1000));
                    });
                });
            }
            var refreshIpsBtn=document.getElementById('cfbcolorvivo-refresh-ips');
            if (refreshIpsBtn){
                refreshIpsBtn.addEventListener('click', function(e){
                    e.preventDefault(); clearConsole(); showWait(true);
                    println('Actualizando IPs del dominio…');
                    refreshSummary(function(res){
                        if (res && res.success) println('IPs actualizadas.');
                    });
                });
            }
        })();";
	}

	/** Return the inline JavaScript for the settings page form. */
	private function get_settings_page_js() {
		return "(function(){
            var form = document.getElementById('cfbcolorvivo-settings-form');
            var warn = document.getElementById('cfbcolorvivo-warn-settings');
            var pre  = document.getElementById('cfbcolorvivo-console-pre-settings');
            if (form) {
                form.addEventListener('submit', function(e){
                    var resetCb = form.querySelector('input[name=\"'+cfbcolorvivoData.optionName+'[reset_settings]\"]');
                    if (resetCb && resetCb.checked) {
                        if (!confirm('ATENCIÓN: Esto borrará TODA la configuración del plugin (credenciales, registros, caché y logs). ¿Continuar?')) {
                            e.preventDefault();
                            return;
                        }
                    }
                    if (warn) warn.style.display = '';
                    if (pre) {
                        var ts = new Date().toLocaleTimeString();
                        pre.textContent += '['+ts+'] Enviando ajustes… verificando credenciales y permisos en Cloudflare.\\n';
                    }
                });
            }
        })();";
	}

	/** Return the inline JavaScript for toggling auth type fields. */
	private function get_auth_type_js() {
		return "document.addEventListener('DOMContentLoaded',function(){
            var sel=document.getElementById('cfbcolorvivo_auth_type');
            var email=document.getElementById('cfbcolorvivo_email_input');
            var emailRow=email?email.closest('tr'):null;
            var accId=document.getElementById('cfbcolorvivo_account_id_input');
            var accRow=accId?accId.closest('tr'):null;
            function t(){
                if(emailRow) emailRow.style.display=(sel.value==='global')?'':'none';
                if(accRow) accRow.style.display=(sel.value==='account_token')?'':'none';
            }
            if(sel){ sel.addEventListener('change',t); t(); }
        });";
	}

	/* ================== Settings API ================== */

	/** Register settings, sections, and fields for the Settings API. */
	public function settings_init() {
		register_setting(
			'cfbcolorvivo_settings_group',
			$this->option_name,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
			)
		);

		add_settings_section( 'cfbcolorvivo_cloudflare_section', __( 'Cloudflare Credentials', 'es-football-bypass-for-cloudflare' ), '__return_false', 'cfbcolorvivo_settings_page' );
		add_settings_field( 'auth_type', __( 'Authentication type', 'es-football-bypass-for-cloudflare' ), array( $this, 'auth_type_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section' );
		add_settings_field( 'cloudflare_email', __( 'Email (Global API Key only)', 'es-football-bypass-for-cloudflare' ), array( $this, 'email_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section' );
		add_settings_field( 'cloudflare_api_key', __( 'Global API Key or Token', 'es-football-bypass-for-cloudflare' ), array( $this, 'api_key_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section' );
		add_settings_field( 'cloudflare_zone_id', __( 'Zone ID', 'es-football-bypass-for-cloudflare' ), array( $this, 'zone_id_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section' );
		add_settings_field( 'cloudflare_account_id', __( 'Account ID (Account Token only)', 'es-football-bypass-for-cloudflare' ), array( $this, 'account_id_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section' );
		add_settings_field( 'server_outgoing_ip', __( 'Server outgoing IP', 'es-football-bypass-for-cloudflare' ), array( $this, 'server_outgoing_ip_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section' );

		add_settings_section( 'cfbcolorvivo_plugin_section', __( 'Plugin Settings', 'es-football-bypass-for-cloudflare' ), '__return_false', 'cfbcolorvivo_settings_page' );
		add_settings_field( 'check_interval', __( 'Check interval (minutes)', 'es-football-bypass-for-cloudflare' ), array( $this, 'check_interval_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'bypass_check_cooldown', __( 'Cooldown after disabling Cloudflare (min)', 'es-football-bypass-for-cloudflare' ), array( $this, 'bypass_check_cooldown_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'force_proxy_off_override', __( 'Force Proxy OFF during football', 'es-football-bypass-for-cloudflare' ), array( $this, 'force_proxy_off_override_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'selected_records', __( 'DNS records to manage (loaded in Operation)', 'es-football-bypass-for-cloudflare' ), array( $this, 'selected_records_hint' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'logging_enabled', __( 'Action logging', 'es-football-bypass-for-cloudflare' ), array( $this, 'logging_enabled_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'log_retention_days', __( 'Log retention (days)', 'es-football-bypass-for-cloudflare' ), array( $this, 'log_retention_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'cron_secret', __( 'External cron token', 'es-football-bypass-for-cloudflare' ), array( $this, 'cron_secret_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
		add_settings_field( 'reset_settings', __( 'Reset settings', 'es-football-bypass-for-cloudflare' ), array( $this, 'reset_settings_render' ), 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section' );
	}

	/**
	 * Sanitize and validate settings input from the settings form or AJAX.
	 *
	 * @param array $input Raw input from the settings form.
	 * @return array Sanitized settings.
	 */
	public function sanitize_settings( $input ) {
		$existing = get_option( $this->option_name, array() );
		$san      = array();

		// Detectar si viene del formulario de configuración (necesario para manejar checkboxes correctamente).
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified by WordPress Settings API before this callback
		$is_settings_form = ! wp_doing_ajax() && isset( $_POST['option_page'] ) && sanitize_text_field( wp_unslash( $_POST['option_page'] ) ) === 'cfbcolorvivo_settings_group';

		// Campos de credenciales / core.
		$san['cloudflare_email']      = isset( $input['cloudflare_email'] ) ? sanitize_email( $input['cloudflare_email'] ) : ( $existing['cloudflare_email'] ?? '' );
		$san['cloudflare_api_key']    = isset( $input['cloudflare_api_key'] ) ? sanitize_text_field( $input['cloudflare_api_key'] ) : ( $existing['cloudflare_api_key'] ?? '' );
		$san['cloudflare_zone_id']    = isset( $input['cloudflare_zone_id'] ) ? sanitize_text_field( $input['cloudflare_zone_id'] ) : ( $existing['cloudflare_zone_id'] ?? '' );
		$san['cloudflare_account_id'] = isset( $input['cloudflare_account_id'] ) ? sanitize_text_field( $input['cloudflare_account_id'] ) : ( $existing['cloudflare_account_id'] ?? '' );
		$auth                         = isset( $input['auth_type'] ) ? sanitize_text_field( $input['auth_type'] ) : ( $existing['auth_type'] ?? 'global' );
		$san['auth_type']             = in_array( $auth, array( 'global', 'token', 'account_token' ), true ) ? $auth : 'global';

		$mins_in               = isset( $input['check_interval'] ) ? intval( $input['check_interval'] ) : ( $existing['check_interval'] ?? 15 );
		$san['check_interval'] = max( 5, min( 60, $mins_in ) );

		// Si llegan desde AJAX estos campos, respetarlos (no pisar).
		$san['dns_records_cache'] = array_key_exists( 'dns_records_cache', $input ) ? $input['dns_records_cache'] : ( $existing['dns_records_cache'] ?? array() );
		$raw_selected             = array_key_exists( 'selected_records', $input ) ? $input['selected_records'] : ( $existing['selected_records'] ?? array() );
		$san['selected_records']  = is_array( $raw_selected ) ? array_map( 'sanitize_text_field', $raw_selected ) : array();

		// Estado persistente.
		$san['dns_cache_last_sync'] = array_key_exists( 'dns_cache_last_sync', $input ) ? sanitize_text_field( $input['dns_cache_last_sync'] ) : ( $existing['dns_cache_last_sync'] ?? '' );
		$san['last_check']          = array_key_exists( 'last_check', $input ) ? sanitize_text_field( $input['last_check'] ) : ( $existing['last_check'] ?? '' );
		$raw_general                = array_key_exists( 'last_status_general', $input ) ? sanitize_text_field( $input['last_status_general'] ) : ( $existing['last_status_general'] ?? 'NO' );
		$san['last_status_general'] = in_array( $raw_general, array( 'SI', 'NO' ), true ) ? $raw_general : 'NO';
		$raw_domain                 = array_key_exists( 'last_status_domain', $input ) ? sanitize_text_field( $input['last_status_domain'] ) : ( $existing['last_status_domain'] ?? 'NO' );
		$san['last_status_domain']  = in_array( $raw_domain, array( 'SI', 'NO' ), true ) ? $raw_domain : 'NO';
		$san['last_update']         = array_key_exists( 'last_update', $input ) ? sanitize_text_field( $input['last_update'] ) : ( $existing['last_update'] ?? '' );
		// FIX: Mismo tratamiento para checkboxes - si viene del formulario y no está marcado, debe ser 0.
		if ( $is_settings_form ) {
			$san['logging_enabled'] = ! empty( $input['logging_enabled'] ) ? 1 : 0;
		} else {
			$san['logging_enabled'] = isset( $input['logging_enabled'] ) ? (int) ! empty( $input['logging_enabled'] ) : ( $existing['logging_enabled'] ?? 1 );
		}
		$san['log_retention_days']    = isset( $input['log_retention_days'] ) ? intval( $input['log_retention_days'] ) : ( $existing['log_retention_days'] ?? 30 );
		$san['bypass_check_cooldown'] = isset( $input['bypass_check_cooldown'] ) ? intval( $input['bypass_check_cooldown'] ) : ( $existing['bypass_check_cooldown'] ?? 60 );
		$san['cron_secret']           = isset( $input['cron_secret'] ) ? sanitize_text_field( $input['cron_secret'] ) : ( $existing['cron_secret'] ?? '' );
		$san['bypass_active']         = isset( $input['bypass_active'] ) ? (int) ! empty( $input['bypass_active'] ) : ( $existing['bypass_active'] ?? 0 );
		$raw_blocked_ips              = array_key_exists( 'bypass_blocked_ips', $input ) ? (array) $input['bypass_blocked_ips'] : ( $existing['bypass_blocked_ips'] ?? array() );
		$san['bypass_blocked_ips']    = array_map( 'sanitize_text_field', $raw_blocked_ips );
		$san['bypass_last_change']    = isset( $input['bypass_last_change'] ) ? intval( $input['bypass_last_change'] ) : ( $existing['bypass_last_change'] ?? 0 );

		// MODIFICACIÓN: Sanitizar force_proxy_off_override
		// FIX: Cuando viene del formulario de configuración, los checkboxes desmarcados no envían nada,
		// así que debemos establecer a 0 si no está presente. Cuando viene de AJAX, mantener el valor existente.
		if ( $is_settings_form ) {
			$san['force_proxy_off_override'] = ! empty( $input['force_proxy_off_override'] ) ? 1 : 0;
		} else {
			$san['force_proxy_off_override'] = isset( $input['force_proxy_off_override'] ) ? (int) ! empty( $input['force_proxy_off_override'] ) : ( $existing['force_proxy_off_override'] ?? 0 );
		}

		$reset_requested = ! empty( $input['reset_settings'] );

		// Normaliza estructuras.
		list($san,) = $this->normalize_settings( $san );

		if ( $reset_requested ) {
			$san = $this->get_default_settings( true );
			$this->clear_logs_file();
			delete_option( 'cfbcolorvivo_settings_last_trace' );
			delete_transient( 'cfbcolorvivo_settings_notice_ok' );
			delete_transient( 'cfbcolorvivo_settings_notice_err' );
			$this->log( 'Configuración reseteada manualmente.' );
		}

		unset( $san['reset_settings'] );

		// Reprogramar cron si cambia intervalo.
		if ( ! isset( $existing['check_interval'] ) || intval( $existing['check_interval'] ) !== intval( $san['check_interval'] ) ) {
			$this->reschedule_cron_after_interval_change();
		}

		// Test sólo si guardas desde la página de ajustes (no AJAX).
		// (variable $is_settings_form ya calculada al inicio de la función).
		if ( $is_settings_form ) {
			$trace = array();
			$ok    = $this->quick_settings_test( $san, $trace );
			// Guardar último log para la consola de Configuración.
			update_option(
				'cfbcolorvivo_settings_last_trace',
				array(
					'ok'    => (bool) $ok,
					'trace' => $trace,
					'ts'    => current_time( 'mysql' ),
				)
			);
			if ( $ok ) {
				set_transient( 'cfbcolorvivo_settings_notice_ok', implode( "\n", $trace ), 60 );
				delete_transient( 'cfbcolorvivo_settings_notice_err' ); } else {
				set_transient( 'cfbcolorvivo_settings_notice_err', implode( "\n", $trace ), 60 );
				delete_transient( 'cfbcolorvivo_settings_notice_ok' ); }
		}

		return $san;
	}

	/** Display admin notices after saving settings. */
	public function settings_save_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only reading page parameter to display notices, no data processing
		if ( isset( $_GET['page'] ) && sanitize_text_field( wp_unslash( $_GET['page'] ) ) === 'cfbcolorvivo-settings' ) {
			$msg = get_transient( 'cfbcolorvivo_settings_notice_ok' );
			if ( $msg ) {
				echo '<div class="notice notice-success"><p><strong>' . esc_html__( 'Connection OK:', 'es-football-bypass-for-cloudflare' ) . '</strong><br><pre style="white-space:pre-wrap">' . esc_html( $msg ) . '</pre></p></div>';
				delete_transient( 'cfbcolorvivo_settings_notice_ok' );
			}
			$msg = get_transient( 'cfbcolorvivo_settings_notice_err' );
			if ( $msg ) {
				echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Connection error:', 'es-football-bypass-for-cloudflare' ) . '</strong><br><pre style="white-space:pre-wrap">' . esc_html( $msg ) . '</pre></p></div>';
				delete_transient( 'cfbcolorvivo_settings_notice_err' );
			}
		}
	}

	/** Unschedule and reschedule the cron event with the current interval. */
	private function reschedule_cron_after_interval_change() {
		$s         = $this->get_settings();
		$interval  = max( 5, min( 60, intval( $s['check_interval'] ) ) );
		$timestamp = wp_next_scheduled( $this->cron_hook );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, $this->cron_hook );
		}
		add_filter(
			'cron_schedules',
			function ( $schedules ) use ( $interval ) {
				$schedules['cf_fb_custom'] = array(
					'interval' => $interval * 60,
					'display'  => 'CFB cada ' . $interval . ' minutos',
				);
				return $schedules;
			}
		);
		wp_schedule_event( time() + 60, 'cf_fb_custom', $this->cron_hook );
	}
	/**
	 * Add a custom cron schedule interval based on plugin settings.
	 *
	 * @param array $schedules Existing cron schedules.
	 * @return array Modified cron schedules.
	 */
	public function add_custom_cron_interval( $schedules ) {
		$s                         = $this->get_settings();
		$interval                  = max( 5, min( 60, intval( $s['check_interval'] ) ) );
		$schedules['cf_fb_custom'] = array(
			'interval' => $interval * 60,
			'display'  => 'CFB cada ' . $interval . ' minutos',
		);
		return $schedules;
	}

	/* ================== Render: Configuración ================== */

	/** Render the plugin settings page. */
	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="wrap"><h1>ES Football Bypass — Configuración</h1>';
		echo '<p>' . esc_html__( 'Saving automatically verifies the connection and permissions (does not alter your DNS cache).', 'es-football-bypass-for-cloudflare' ) . '</p>';
		echo '<form id="cfbcolorvivo-settings-form" method="post" action="options.php">';
		settings_fields( 'cfbcolorvivo_settings_group' );
		do_settings_sections( 'cfbcolorvivo_settings_page' );
		submit_button( 'Guardar cambios y verificar' );
		echo '</form>';

		// Consola propia de Configuración (muestra último log guardado).
		$last = get_option( 'cfbcolorvivo_settings_last_trace' );
		echo '<div class="notice notice-info" style="padding:10px;white-space:pre-wrap;line-height:1.3;margin-top:10px">';
		echo '<strong>' . esc_html__( 'Console:', 'es-football-bypass-for-cloudflare' ) . '</strong>';
		echo '<div id="cfbcolorvivo-warn-settings" style="color:#b32d2e;font-weight:600;margin:6px 0 0 0;display:none;">' . esc_html__( '⏳ Wait a few seconds for the operation to complete…', 'es-football-bypass-for-cloudflare' ) . '</div>';
		echo '<pre id="cfbcolorvivo-console-pre-settings" style="margin:6px 0 0 0;white-space:pre-wrap;">';
		if ( is_array( $last ) && ! empty( $last['trace'] ) ) {
			foreach ( $last['trace'] as $line ) {
				echo esc_html( $line ) . "\n";
			}
		}
		echo '</pre></div>';
		$plugin_data = get_plugin_data( __FILE__ );
		echo '<p style="text-align:right;color:#999;font-size:12px;margin-top:20px;">' . esc_html( 'Version ' . $plugin_data['Version'] ) . '</p>';
		echo '</div>';
	}

	/** Render the logs viewer page. */
	public function render_logs_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s       = $this->get_settings();
		$path    = $this->get_log_file_path();
		$enabled = ! empty( $s['logging_enabled'] );
		$entries = $enabled ? $this->read_log_entries( 250 ) : array();
		echo '<div class="wrap"><h1>ES Football Bypass — Logs</h1>';
		echo '<p>Archivo: <code>' . esc_html( $path ) . '</code></p>';
		echo '<p>Estado: <strong>' . esc_html( $enabled ? __( 'Active', 'es-football-bypass-for-cloudflare' ) : __( 'Disabled', 'es-football-bypass-for-cloudflare' ) ) . '</strong>. ';
		// translators: %d is the number of days for log retention.
		printf( '%s</p>', esc_html( sprintf( __( 'Retention: %d days.', 'es-football-bypass-for-cloudflare' ), intval( $s['log_retention_days'] ?? 30 ) ) ) );
		if ( ! $enabled ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Logging is disabled. Enable it in the Settings tab.', 'es-football-bypass-for-cloudflare' ) . '</p></div>';
		}
		if ( $enabled && empty( $entries ) ) {
			if ( ! file_exists( $path ) ) {
				echo '<p>' . esc_html__( 'No events recorded yet.', 'es-football-bypass-for-cloudflare' ) . '</p>';
			} else {
				echo '<p>' . esc_html__( 'The log file exists but contains no recent events.', 'es-football-bypass-for-cloudflare' ) . '</p>';
			}
		}
		if ( $enabled && ! empty( $entries ) ) {
			echo '<table class="widefat striped" style="margin-top:15px">';
			echo '<thead><tr><th>' . esc_html__( 'Date', 'es-football-bypass-for-cloudflare' ) . '</th><th>' . esc_html__( 'Type', 'es-football-bypass-for-cloudflare' ) . '</th><th>' . esc_html__( 'Message', 'es-football-bypass-for-cloudflare' ) . '</th><th>' . esc_html__( 'Context', 'es-football-bypass-for-cloudflare' ) . '</th></tr></thead><tbody>';
			foreach ( $entries as $entry ) {
				echo '<tr>';
				echo '<td>' . esc_html( $entry['time'] ?? '' ) . '</td>';
				echo '<td>' . esc_html( $entry['type'] ?? 'info' ) . '</td>';
				echo '<td>' . esc_html( $entry['message'] ?? '' ) . '</td>';
				echo '<td>';
				if ( ! empty( $entry['context'] ) && is_array( $entry['context'] ) ) {
					echo esc_html( wp_json_encode( $entry['context'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
				}
				echo '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
			echo '<p style="margin-top:10px;font-size:12px;color:#666">' . esc_html__( 'Showing the 250 most recent events.', 'es-football-bypass-for-cloudflare' ) . '</p>';
		}
		$plugin_data = get_plugin_data( __FILE__ );
		echo '<p style="text-align:right;color:#999;font-size:12px;margin-top:20px;">' . esc_html( 'Version ' . $plugin_data['Version'] ) . '</p>';
		echo '</div>';
	}

	/** Render the authentication type selector field. */
	public function auth_type_render() {
		$s = $this->get_settings(); ?>
		<select name="<?php echo esc_attr( $this->option_name ); ?>[auth_type]" id="cfbcolorvivo_auth_type">
			<option value="global"        <?php selected( $s['auth_type'], 'global' ); ?>>Global API Key</option>
			<option value="token"         <?php selected( $s['auth_type'], 'token' ); ?>>API Token de usuario (Bearer)</option>
			<option value="account_token" <?php selected( $s['auth_type'], 'account_token' ); ?>>API Token de cuenta (Bearer)</option>
		</select>
		<p class="description"><?php echo esc_html__( 'Global API Key requires email. User tokens are in My Profile. Account tokens are in Manage Account > Account API Tokens (requires Super Administrator). Minimum permissions: Zone:Read, DNS:Read, DNS:Edit.', 'es-football-bypass-for-cloudflare' ); ?></p>
		<?php
	}
	/** Render the Cloudflare email input field. */
	public function email_render() {
		$s = $this->get_settings();
		printf(
			'<input id="cfbcolorvivo_email_input" type="email" name="%1$s[cloudflare_email]" value="%2$s" class="regular-text" autocomplete="off" />',
			esc_attr( $this->option_name ),
			esc_attr( $s['cloudflare_email'] )
		);
	}
	/** Render the API key/token input field. */
	public function api_key_render() {
		$s = $this->get_settings();
		?>
		<input type="password" autocomplete="new-password" name="<?php echo esc_attr( $this->option_name ); ?>[cloudflare_api_key]" value="<?php echo esc_attr( $s['cloudflare_api_key'] ); ?>" class="regular-text" />
		<p class="description"><?php echo esc_html__( 'Never shown in traces or console.', 'es-football-bypass-for-cloudflare' ); ?></p>
		<?php
	}
	/** Render the Zone ID input field. */
	public function zone_id_render() {
		$s = $this->get_settings();
		?>
		<input type="text" name="<?php echo esc_attr( $this->option_name ); ?>[cloudflare_zone_id]" value="<?php echo esc_attr( $s['cloudflare_zone_id'] ); ?>" class="regular-text" />
		<?php
	}
	/** Render the Account ID input field. */
	public function account_id_render() {
		$s = $this->get_settings();
		?>
		<input type="text" name="<?php echo esc_attr( $this->option_name ); ?>[cloudflare_account_id]" value="<?php echo esc_attr( $s['cloudflare_account_id'] ?? '' ); ?>" class="regular-text" id="cfbcolorvivo_account_id_input" />
		<p class="description"><?php esc_html_e( 'Required only for account tokens. You can find it in the URL of the Cloudflare dashboard: dash.cloudflare.com/ACCOUNT_ID', 'es-football-bypass-for-cloudflare' ); ?></p>
		<?php
	}
	/** Render the server outgoing IP display field. */
	public function server_outgoing_ip_render() {
		$ips = $this->get_server_outgoing_ips();
		if ( empty( $ips ) ) {
			echo '<code>' . esc_html__( 'Could not be detected', 'es-football-bypass-for-cloudflare' ) . '</code>';
			echo '<p class="description">' . esc_html__( 'The server outgoing IP could not be determined. Verify that the server has Internet access.', 'es-football-bypass-for-cloudflare' ) . '</p>';
		} elseif ( count( $ips ) === 1 ) {
			echo '<code style="font-size:14px;padding:4px 8px;background:#f0f0f1;">' . esc_html( $ips[0] ) . '</code>';
			echo '<p class="description">' . esc_html__( 'This is the IP your server uses to communicate with the Cloudflare API. You can restrict your API Token to this IP for added security.', 'es-football-bypass-for-cloudflare' ) . '</p>';
		} else {
			foreach ( $ips as $i => $ip ) {
				if ( $i > 0 ) {
					echo ' ';
				}
				echo '<code style="font-size:14px;padding:4px 8px;background:#f0f0f1;">' . esc_html( $ip ) . '</code>';
			}
			echo '<p class="description">' . esc_html__( 'Multiple outgoing IPs have been detected. Your server may use any of them to communicate with the Cloudflare API. Add all of them when restricting your API Token.', 'es-football-bypass-for-cloudflare' ) . '</p>';
		}
	}
	/** Render the check interval input field. */
	public function check_interval_render() {
		$s = $this->get_settings();
		printf(
			'<input type="number" min="5" max="60" name="%1$s[check_interval]" value="%2$d" class="small-text" />',
			esc_attr( $this->option_name ),
			intval( $s['check_interval'] )
		);
	}
	/** Render the selected records hint text. */
	public function selected_records_hint() {
		echo '<p class="description">' . wp_kses( __( 'Select the records to manage in the <strong>Operation</strong> tab (using the cache).', 'es-football-bypass-for-cloudflare' ), array( 'strong' => array() ) ) . '</p>';
	}
	/** Render the bypass cooldown input field. */
	public function bypass_check_cooldown_render() {
		$s   = $this->get_settings();
		$val = isset( $s['bypass_check_cooldown'] ) ? intval( $s['bypass_check_cooldown'] ) : 60;
		printf(
			'<input type="number" min="5" max="1440" name="%1$s[bypass_check_cooldown]" value="%2$d" class="small-text" />',
			esc_attr( $this->option_name ),
			esc_attr( $val )
		);
		echo '<p class="description">' . esc_html__( 'Minutes that must pass after disabling Cloudflare before checking if it can be reactivated (5-1440).', 'es-football-bypass-for-cloudflare' ) . '</p>';
	}

	/** Render the force proxy off override checkbox field. */
	public function force_proxy_off_override_render() {
		$s       = $this->get_settings();
		$checked = ! empty( $s['force_proxy_off_override'] ) ? 'checked' : '';
		echo '<label><input type="checkbox" name="' . esc_attr( $this->option_name ) . '[force_proxy_off_override]" value="1" ' . esc_attr( $checked ) . '> ' . esc_html__( 'Disable Proxy during football (General=YES), without waiting for this domain detection', 'es-football-bypass-for-cloudflare' ) . '</label>';
		echo '<p class="description" style="color:#d63638;font-weight:600;">' . esc_html__( 'IMPORTANT: With this option enabled, the proxy will be automatically disabled when hayahora.futbol indicates active blocks (General=YES), even if your specific domain has not been detected as blocked.', 'es-football-bypass-for-cloudflare' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Useful to avoid false negatives when you know your site is blocked during football events but IP detection doesn\'t always work correctly.', 'es-football-bypass-for-cloudflare' ) . '</p>';
	}

	/** Render the logging enabled checkbox field. */
	public function logging_enabled_render() {
		$s       = $this->get_settings();
		$checked = ! empty( $s['logging_enabled'] ) ? 'checked' : '';
		echo '<label><input type="checkbox" name="' . esc_attr( $this->option_name ) . '[logging_enabled]" value="1" ' . esc_attr( $checked ) . '> ' . esc_html__( 'Save actions to log (cron and manual)', 'es-football-bypass-for-cloudflare' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Logs are stored in the uploads directory, protected with .htaccess, and displayed in the Logs tab.', 'es-football-bypass-for-cloudflare' ) . '</p>';
	}
	/** Render the log retention days input field. */
	public function log_retention_render() {
		$s    = $this->get_settings();
		$days = isset( $s['log_retention_days'] ) ? intval( $s['log_retention_days'] ) : 30;
		printf(
			'<input type="number" min="1" max="365" name="%1$s[log_retention_days]" value="%2$d" class="small-text" />',
			esc_attr( $this->option_name ),
			esc_attr( $days )
		);
		echo '<p class="description">' . esc_html__( 'Number of days to keep logs (minimum 1).', 'es-football-bypass-for-cloudflare' ) . '</p>';
	}
	/** Render the external cron secret token field. */
	public function cron_secret_render() {
		$s      = $this->get_settings();
		$secret = isset( $s['cron_secret'] ) ? $s['cron_secret'] : '';
		echo '<input type="text" name="' . esc_attr( $this->option_name ) . '[cron_secret]" style="width:320px" id="cfbcolorvivo-cron-secret" value="' . esc_attr( $secret ) . '" autocomplete="off" />';
		echo '<p class="description">' . esc_html__( 'Use this token in external cron:', 'es-football-bypass-for-cloudflare' ) . '</p>';
		$url = add_query_arg(
			array(
				'cfbcolorvivo_cron' => 1,
				'token'             => $secret,
			),
			home_url( '/wp-cron.php' )
		);
		echo '<code>' . esc_html( $url ) . '</code>';
		echo '<p class="description">' . esc_html__( 'You can regenerate the token by deleting it and saving settings (a new one will be created).', 'es-football-bypass-for-cloudflare' ) . '</p>';
	}
	/** Render the reset settings checkbox field. */
	public function reset_settings_render() {
		echo '<label><input type="checkbox" name="' . esc_attr( $this->option_name ) . '[reset_settings]" value="1"> ' . esc_html__( 'Delete all plugin settings on save', 'es-football-bypass-for-cloudflare' ) . '</label>';
		echo '<p class="description" style="color:#b32d2e">' . esc_html__( 'This action deletes credentials, selected records, DNS cache and logs. You will need to configure the plugin again.', 'es-football-bypass-for-cloudflare' ) . '</p>';
	}

	/* ================== Render: Operación ================== */

	/** Render the main operation page with DNS table and action buttons. */
	public function render_main_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$s        = $this->get_settings();
		$domain   = $this->get_site_domain();
		$is_local = $this->is_local_domain( $domain );

		if ( $is_local ) {
			echo '<div class="wrap"><h1>ES Football Bypass — Operación</h1>';
			echo '<div class="notice notice-warning" style="padding:12px;">';
			echo '<p><strong>' . esc_html__( 'Local environment detected', 'es-football-bypass-for-cloudflare' ) . '</strong></p>';
			echo '<p>' . sprintf(
				/* translators: %s is the detected domain */
				esc_html__( 'The current domain is %s, which corresponds to a local environment or an IP address. This plugin needs a public domain accessible from the Internet to work correctly (DNS resolution, Cloudflare API and block checking).', 'es-football-bypass-for-cloudflare' ),
				'<code>' . esc_html( $domain ) . '</code>'
			) . '</p>';
			echo '<p>' . esc_html__( 'Install the plugin on your production or staging site with a real domain to use it.', 'es-football-bypass-for-cloudflare' ) . '</p>';
			echo '</div>';
			echo '<p style="margin-top:15px;"><a href="' . esc_url( admin_url( 'admin.php?page=cfbcolorvivo-settings' ) ) . '" class="button">' . esc_html__( 'Go to Settings', 'es-football-bypass-for-cloudflare' ) . '</a></p>';
			$plugin_data = get_plugin_data( __FILE__ );
			echo '<p style="text-align:right;color:#999;font-size:12px;margin-top:20px;">' . esc_html( 'Version ' . $plugin_data['Version'] ) . '</p>';
			echo '</div>';
			return;
		}

		$sync_trace = array();
		if ( ! empty( $s['cloudflare_zone_id'] ) && ! empty( $s['cloudflare_api_key'] ) ) {
			$records = $this->fetch_dns_records( array( 'A', 'AAAA', 'CNAME' ), $sync_trace );
			if ( ! empty( $records ) ) {
				$this->persist_dns_cache( $records );
				$this->log_event(
					'manual',
					'Vista Operación: caché DNS sincronizada',
					array(
						'usuario'   => $this->current_user_label(),
						'registros' => count( $records ),
					)
				);
				$s = $this->get_settings();
			} elseif ( ! empty( $sync_trace ) ) {
				$this->log_event(
					'manual',
					'Vista Operación: no se pudo sincronizar DNS',
					array(
						'usuario' => $this->current_user_label(),
						'detalle' => $sync_trace,
					)
				);
			}
		}
		$cache     = isset( $s['dns_records_cache'] ) ? $s['dns_records_cache'] : array();
		$sel       = isset( $s['selected_records'] ) ? $s['selected_records'] : array();
		$nonce     = wp_create_nonce( 'cfbcolorvivo_nonce' );
		$domain    = $this->get_site_domain();
		$check_url = 'https://hayahora.futbol/#comprobador&domain=' . rawurlencode( $domain );

		echo '<div class="wrap"><h1>ES Football Bypass — Operación</h1>';

		// Intro solicitada.
		echo '<p style="max-width:960px;margin-top:6px">';
		echo 'ES Football Bypass es un plugin gratis creado por <a href="' . esc_url( 'https://colorvivo.com' ) . '" target="_blank" rel="noopener">Color Vivo</a> y ';
		echo '<a href="' . esc_url( 'https://carrero.es' ) . '" target="_blank" rel="noopener">David Carrero Fernandez-Baillo</a> para ayudar a que si tu WordPress se ve afectado por los bloqueos indiscriminados de la liga ';
		echo 'puedas desactivar el CDN temporalmente. Sabemos que no es la mejor solución pero al menos no perdemos visitas.';
		echo '</p>';

		// Layout a 2 columnas.
		echo '<div class="cfbcolorvivo-flex" style="display:flex;gap:20px;align-items:flex-start;">';

		// Columna izquierda (principal).
		echo '<div class="cfbcolorvivo-main" style="flex:1;min-width:0;">';

		$auth_label = array(
			'global'        => 'Global Key',
			'token'         => 'Token usuario',
			'account_token' => 'Token cuenta',
		);
		echo '<p>Zona: <code>' . esc_html( $this->mask( $s['cloudflare_zone_id'] ) ) . '</code> · Auth: <strong>' . esc_html( $auth_label[ $s['auth_type'] ] ?? $s['auth_type'] ) . '</strong> · ';
		echo 'Dominio: <strong>' . esc_html( $domain ) . '</strong> — <a href="' . esc_url( $check_url ) . '" target="_blank" rel="noopener">Abrir comprobador</a></p>';

		echo '<h2 class="title">Registros DNS en caché</h2>';
		echo '<p class="description">Debes seleccionar los registros que debemos controlar y pulsar "Probar conexión y cargar DNS" para actualizar el listado.</p>';
		echo '<div id="cfbcolorvivo-dns-list">';
		if ( empty( $cache ) ) {
			echo '<p>No hay registros en caché. Pulsa "Probar conexión y cargar DNS".</p>';
		} else {
			$this->echo_dns_table( $cache, $sel );
		}
		echo '</div>';

		echo '<p style="margin-top:10px">';
		echo '<button class="button button-primary" id="cfbcolorvivo-test" data-nonce="' . esc_attr( $nonce ) . '">Probar conexión y cargar DNS</button> ';
		echo '<button class="button" id="cfbcolorvivo-check">Comprobación manual ahora</button> ';
		echo '<button class="button" id="cfbcolorvivo-off">Forzar Proxy OFF (DNS Only)</button> ';
		echo '<button class="button" id="cfbcolorvivo-on">Forzar Proxy ON (CDN)</button> ';
		echo '<button class="button" id="cfbcolorvivo-diag">Diagnóstico WP-Cron</button>';
		echo '</p>';

		echo '<div id="cfbcolorvivo-console" class="notice notice-info" style="padding:10px;white-space:pre-wrap;line-height:1.3">';
		echo '<strong>Consola:</strong>';
		echo '<div id="cfbcolorvivo-warn" style="color:#b32d2e;font-weight:600;margin:6px 0 0 0;display:none;">⏳ Espera unos segundos para que se complete la operación…</div>';
		echo '<pre id="cfbcolorvivo-console-pre" style="margin:6px 0 0 0;white-space:pre-wrap;"></pre>';
		echo '</div>';

		$calc          = $this->compute_statuses_from_json( true );
		$general_si_no = ( 'SÍ' === $calc['general'] ) ? 'SI' : 'NO';
		$domain_si_no  = ( 'SÍ' === $calc['domain'] ) ? 'SI' : 'NO';
		$ips_str       = ! empty( $calc['domain_ips'] ) ? esc_html( implode( ', ', $calc['domain_ips'] ) ) : '—';
		$last_update   = $calc['last_update'] ? $calc['last_update'] : '—';

		echo '<div class="cfbcolorvivo-summary" style="margin-top:10px">';
		echo '<p><strong>Hay bloqueos en algunas IPs ahora:</strong> <span id="cfbcolorvivo-summary-general">' . esc_html( $general_si_no ) . '</span></p>';
		echo '<p><strong>¿Está este dominio ' . esc_html( $domain ) . ' bloqueado?</strong> <span id="cfbcolorvivo-summary-domain">' . esc_html( $domain_si_no ) . '</span> (IPs: <span id="cfbcolorvivo-summary-ips">' . esc_html( $ips_str ) . '</span> <a href="#" id="cfbcolorvivo-refresh-ips" class="button-link">Actualizar IPs</a>)</p>';
		echo '<p><strong>Última actualización (JSON de IPs):</strong> <span id="cfbcolorvivo-summary-lastupdate">' . esc_html( $last_update ) . '</span></p>';
		echo '</div>';

		echo '</div>'; // .cfbcolorvivo-main

		// Columna derecha (sidebar).
		echo '<aside class="cfbcolorvivo-aside" style="width:320px;max-width:100%;">';

		echo '<div class="postbox" style="padding:12px;">';
		echo '<h3 style="margin:0 0 10px 0;">#LaLigaGate</h3>';
		echo '<ul style="margin:0;padding-left:18px;">';
		echo '<li><a href="' . esc_url( 'https://hayahora.futbol/' ) . '" target="_blank" rel="noopener">Hay ahora fútbol</a></li>';
		echo '<li><a href="' . esc_url( 'https://laligagate.com/' ) . '" target="_blank" rel="noopener">Web La Liga Gate</a></li>';
		echo '<li><a href="' . esc_url( 'https://x.com/laligagate' ) . '" target="_blank" rel="noopener">Sigue en X @LaLigaGate</a></li>';
		echo '</ul>';
		echo '</div>';

		echo '<div class="postbox" style="padding:12px;">';
		echo '<h3 style="margin:0 0 10px 0;">Servidores VPN</h3>';
		echo '<ul style="margin:0;padding-left:18px;">';
		echo '<li><a href="' . esc_url( 'https://revistacloud.com/protonvpn' ) . '" target="_blank" rel="noopener">VPN Proton (aff)</a></li>';
		echo '<li><a href="' . esc_url( 'https://revistacloud.com/nvpn' ) . '" target="_blank" rel="noopener">NordVPN (aff)</a></li>';
		echo '</ul>';
		echo '</div>';

		echo '<div class="postbox" style="padding:12px;">';
		echo '<h3 style="margin:0 0 10px 0;">Noticias y actualidad</h3>';
		echo '<ul style="margin:0;padding-left:18px;">';
		echo '<li><a href="' . esc_url( 'https://revistacloud.com' ) . '" target="_blank" rel="noopener">Actualidad Revista Cloud</a></li>';
		echo '<li><a href="' . esc_url( 'https://redes-sociales.com' ) . '" target="_blank" rel="noopener">Noticias Redes Sociales</a></li>';
		echo '<li><a href="' . esc_url( 'https://wpdirecto.com' ) . '" target="_blank" rel="noopener">WordPress Directo</a></li>';
		echo '</ul>';
		echo '</div>';

		echo '<div class="postbox" style="padding:12px;">';
		echo '<h3 style="margin:0 0 10px 0;">Enlaces Seguridad</h3>';
		echo '<ul style="margin:0;padding-left:18px;">';
		echo '<li><a href="' . esc_url( 'https://revistacloud.com/backblaze' ) . '" target="_blank" rel="noopener">Backup para tu Ordenador (aff)</a></li>';
		echo '<li><a href="' . esc_url( 'https://revistacloud.com/1passwordes' ) . '" target="_blank" rel="noopener">Gestor de contraseñas (aff)</a></li>';
		echo '<li><a href="' . esc_url( 'https://opensecurity.es' ) . '" target="_blank" rel="noopener">Noticias OpenSecurity</a></li>';
		echo '</ul>';
		echo '<div style="text-align:center;margin-top:12px;padding-top:10px;border-top:1px solid #e2e2e2;">';
		echo '<p style="font-size:11px;color:#666;margin:0;">Desarrollado por <a href="' . esc_url( 'https://carrero.es' ) . '" target="_blank" rel="noopener">David Carrero Fernandez-Baillo</a></p>';
		echo '</div>';
		echo '</div>';

		echo '</aside>';

		echo '</div>'; // .cfbcolorvivo-flex
		$plugin_data = get_plugin_data( __FILE__ );
		echo '<p style="text-align:right;color:#999;font-size:12px;margin-top:20px;">' . esc_html( 'Version ' . $plugin_data['Version'] ) . '</p>';
		echo '</div>';
	}

	/**
	 * Output the DNS records table with selection checkboxes.
	 *
	 * @param array $records  DNS record arrays to display.
	 * @param array $selected Currently selected record IDs.
	 */
	private function echo_dns_table( $records, $selected ) {
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th style="width:28px;"></th><th>Nombre</th><th>Tipo</th><th>Contenido</th><th>Proxied</th><th>TTL</th>';
		echo '</tr></thead><tbody>';
		foreach ( $records as $r ) {
			$id      = $r['id'] ?? '';
			$name    = $r['name'] ?? '';
			$type    = $r['type'] ?? '';
			$cont    = $r['content'] ?? '';
			$px      = array_key_exists( 'proxied', $r ) ? $r['proxied'] : null;
			$ttl     = $r['ttl'] ?? '';
			$checked = in_array( $id, (array) $selected, true ) ? ' checked' : '';
			echo '<tr>';
			echo '<td><input type="checkbox" name="' . esc_attr( $this->option_name ) . '[selected_records][]" value="' . esc_attr( $id ) . '"' . esc_attr( $checked ) . '></td>';
			echo '<td>' . esc_html( $name ) . '</td>';
			echo '<td>' . esc_html( $type ) . '</td>';
			echo '<td>' . esc_html( $cont ) . '</td>';
			echo '<td>' . ( null === $px ? '—' : ( $px ? 'ON' : 'OFF' ) ) . '</td>';
			echo '<td>' . esc_html( $ttl ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	/* ================== Verificación rápida (para settings) ================== */

	/**
	 * Build the HTTP headers array for Cloudflare API requests.
	 *
	 * @param array $settings Plugin settings with auth credentials.
	 * @return array HTTP headers for the API request.
	 */
	private function api_headers( $settings ) {
		$h = array( 'Content-Type' => 'application/json' );
		if ( 'global' === $settings['auth_type'] ) {
			$h['X-Auth-Email'] = $settings['cloudflare_email'];
			$h['X-Auth-Key']   = $settings['cloudflare_api_key'];
		} else {
			$h['Authorization'] = 'Bearer ' . $settings['cloudflare_api_key'];
		}
		return $h;
	}

	/**
	 * Test Cloudflare API connectivity and permissions with the given settings.
	 *
	 * @param array $settings Plugin settings to test.
	 * @param array $trace    Trace log array, passed by reference.
	 * @return bool True if connection and permissions are valid.
	 */
	private function quick_settings_test( $settings, &$trace ) {
		if ( empty( $settings['cloudflare_api_key'] ) ) {
			$this->trace( $trace, 'Falta API Key/Token.' );
			return false; }
		if ( empty( $settings['cloudflare_zone_id'] ) ) {
			$this->trace( $trace, 'Falta Zone ID.' );
			return false; }
		if ( 'global' === $settings['auth_type'] && empty( $settings['cloudflare_email'] ) ) {
			$this->trace( $trace, 'Falta email para Global API Key.' );
			return false; }
		if ( 'account_token' === $settings['auth_type'] && empty( $settings['cloudflare_account_id'] ) ) {
			$this->trace( $trace, 'Falta Account ID para token de cuenta.' );
			return false; }

		$headers = $this->api_headers( $settings );

		if ( 'account_token' === $settings['auth_type'] ) {
			$url = 'https://api.cloudflare.com/client/v4/accounts/' . rawurlencode( $settings['cloudflare_account_id'] ) . '/tokens/verify';
			$this->trace( $trace, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				$this->trace( $trace, 'WP_Error verify: ' . $r->get_error_message() );
				return false; }
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$json  = json_decode( $body, true );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			$this->trace( $trace, 'verify HTTP ' . $code . ' success=' . ( ( ! empty( $json['success'] ) ) ? 'true' : 'false' ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				$err = isset( $json['errors'][0]['message'] ) ? $json['errors'][0]['message'] : 'verify failed';
				$this->trace( $trace, 'Error: ' . $err );
				return false;
			}
		} elseif ( 'token' === $settings['auth_type'] ) {
			$url = 'https://api.cloudflare.com/client/v4/user/tokens/verify';
			$this->trace( $trace, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				$this->trace( $trace, 'WP_Error verify: ' . $r->get_error_message() );
				return false; }
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$json  = json_decode( $body, true );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			$this->trace( $trace, 'verify HTTP ' . $code . ' success=' . ( ( ! empty( $json['success'] ) ) ? 'true' : 'false' ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				$err = isset( $json['errors'][0]['message'] ) ? $json['errors'][0]['message'] : 'verify failed';
				$this->trace( $trace, 'Error: ' . $err );
				return false;
			}
		} else {
			$url = 'https://api.cloudflare.com/client/v4/user';
			$this->trace( $trace, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				$this->trace( $trace, 'WP_Error user: ' . $r->get_error_message() );
				return false; }
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$json  = json_decode( $body, true );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			$this->trace( $trace, 'user HTTP ' . $code . ' success=' . ( ( ! empty( $json['success'] ) ) ? 'true' : 'false' ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				$this->trace( $trace, 'Error autenticando Global Key.' );
				return false; }
		}

		$url = 'https://api.cloudflare.com/client/v4/zones/' . rawurlencode( $settings['cloudflare_zone_id'] );
		$this->trace( $trace, 'GET ' . $url );
		$r = wp_remote_get(
			$url,
			array(
				'headers' => $headers,
				'timeout' => 20,
			)
		);
		if ( is_wp_error( $r ) ) {
			$this->trace( $trace, 'WP_Error zone: ' . $r->get_error_message() );
			return false; }
		$code      = wp_remote_retrieve_response_code( $r );
		$body      = wp_remote_retrieve_body( $r );
		$json      = json_decode( $body, true );
		$cf_ray     = wp_remote_retrieve_header( $r, 'cf-ray' );
		$zone_name = is_array( $json ) && ! empty( $json['result']['name'] ) ? $json['result']['name'] : '?';
		$this->trace( $trace, 'zone HTTP ' . $code . ' success=' . ( ( ! empty( $json['success'] ) ) ? 'true' : 'false' ) . ' name=' . $zone_name . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
		if ( 200 !== $code || empty( $json['success'] ) ) {
			$this->trace( $trace, 'Error accediendo a la zona (ID o permisos).' );
			return false; }

		$site_domain = $this->get_site_domain();
		if ( ! $this->domain_matches_zone( $site_domain, $zone_name ) ) {
			$this->trace( $trace, 'Zone mismatch: dominio=' . $site_domain . ' zona=' . $zone_name );
			return false;
		}

		$url = 'https://api.cloudflare.com/client/v4/zones/' . rawurlencode( $settings['cloudflare_zone_id'] ) . '/dns_records?per_page=50&page=1';
		$this->trace( $trace, 'GET ' . $url );
		$r = wp_remote_get(
			$url,
			array(
				'headers' => $headers,
				'timeout' => 30,
			)
		);
		if ( is_wp_error( $r ) ) {
			$this->trace( $trace, 'WP_Error dns: ' . $r->get_error_message() );
			return false; }
		$code  = wp_remote_retrieve_response_code( $r );
		$body  = wp_remote_retrieve_body( $r );
		$json  = json_decode( $body, true );
		$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
		$this->trace( $trace, 'dns HTTP ' . $code . ' success=' . ( ( ! empty( $json['success'] ) ) ? 'true' : 'false' ) . ' count=' . ( isset( $json['result'] ) ? count( $json['result'] ) : 0 ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
		if ( 200 !== $code || empty( $json['success'] ) ) {
			$err = isset( $json['errors'][0]['message'] ) ? $json['errors'][0]['message'] : 'dns list failed';
			$this->trace( $trace, 'Error DNS: ' . $err );
			return false;
		}
		$this->trace( $trace, 'Conexion OK y lectura de DNS disponible.' );
		return true;
	}

	/* ================== Cloudflare: lectura/edición ================== */

	/**
	 * Fetch DNS records from the Cloudflare API, paginated.
	 *
	 * @param array      $allowed_types DNS record types to include.
	 * @param array|null $trace         Optional trace log array, passed by reference.
	 * @return array Fetched DNS record arrays.
	 */
	private function fetch_dns_records( array $allowed_types = array( 'A', 'AAAA', 'CNAME' ), &$trace = null ) {
		$s = $this->get_settings();
		if ( empty( $s['cloudflare_api_key'] ) || empty( $s['cloudflare_zone_id'] ) ) {
			$this->trace( $trace, 'CF API DNS: falta API key o Zone ID.' );
			return array(); }
		if ( 'global' === $s['auth_type'] && empty( $s['cloudflare_email'] ) ) {
			$this->trace( $trace, 'CF API DNS: falta email para Global API Key.' );
			return array(); }
		$headers = $this->api_headers( $s );

		$page        = 1;
		$per_page    = 100;
		$accum       = array();
		$max_pages   = 50;
		$total_pages = 1;
		do {
			$url = 'https://api.cloudflare.com/client/v4/zones/' . rawurlencode( $s['cloudflare_zone_id'] ) . '/dns_records?per_page=' . $per_page . '&page=' . $page;
			$this->trace( $trace, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 30,
				)
			);
			if ( is_wp_error( $r ) ) {
				$this->trace( $trace, 'CF API DNS WP_Error: ' . $r->get_error_message() );
				break; }
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			if ( 200 !== $code ) {
				$this->trace( $trace, 'CF API DNS HTTP ' . $code . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) . ' body: ' . substr( (string) $body, 0, 300 ) );
				break; }
			if ( ! $body ) {
				$this->trace( $trace, 'CF API DNS: cuerpo vacio.' );
				break; }
			$json = json_decode( $body, true );
			if ( ! is_array( $json ) ) {
				$this->trace( $trace, 'CF API DNS: JSON invalido: ' . substr( (string) $body, 0, 300 ) );
				break; }
			if ( empty( $json['success'] ) ) {
				$this->trace( $trace, 'CF API DNS: success=false err=' . substr( wp_json_encode( $json['errors'] ), 0, 300 ) );
				break; }
			if ( ! isset( $json['result'] ) ) {
				$this->trace( $trace, 'CF API DNS: sin result.' );
				break; }

			$ri = $json['result_info'] ?? null;
			if ( $ri && isset( $ri['total_count'], $ri['per_page'] ) && intval( $ri['per_page'] ) > 0 ) {
				$total_pages = (int) ceil( $ri['total_count'] / $ri['per_page'] );
				$this->trace( $trace, 'result_info: count=' . ( isset( $ri['count'] ) ? $ri['count'] : '?' ) . ' total=' . $ri['total_count'] . ' per_page=' . $ri['per_page'] . ' page=' . $ri['page'] . ' total_pages=' . $total_pages );
			} else {
				$this->trace( $trace, 'result_info no disponible; se asume 1 pagina.' );
				$total_pages = $page;
			}

			foreach ( $json['result'] as $rr ) {
				$t = isset( $rr['type'] ) ? strtoupper( $rr['type'] ) : '';
				if ( ! in_array( $t, $allowed_types, true ) ) {
					continue;
				}
				$accum[] = array(
					'id'      => (string) ( $rr['id'] ?? '' ),
					'name'    => (string) ( $rr['name'] ?? '' ),
					'type'    => $t,
					'content' => (string) ( $rr['content'] ?? '' ),
					'proxied' => array_key_exists( 'proxied', $rr ) ? (bool) $rr['proxied'] : null,
					'ttl'     => intval( $rr['ttl'] ?? 1 ),
				);
			}
			$this->trace( $trace, 'Pagina ' . $page . ' leida. Acumulados=' . count( $accum ) );
			++$page;
		} while ( $page <= $total_pages && $page <= $max_pages );

		return $accum;
	}

	/**
	 * Update the proxy status of a single DNS record via the Cloudflare API.
	 *
	 * @param string $record_id  Cloudflare DNS record ID.
	 * @param bool   $proxied_on Whether to enable proxy (true) or DNS only (false).
	 * @param bool   $detailed   Whether to return detailed result array.
	 * @return bool|array True/false on success/failure, or detailed array.
	 */
	private function update_record_proxy_status( $record_id, $proxied_on, $detailed = false ) {
		$s = $this->get_settings();
		if ( empty( $s['cloudflare_api_key'] ) || empty( $s['cloudflare_zone_id'] ) ) {
			return $detailed ? array(
				'success' => false,
				'error'   => 'Falta API key o Zone ID',
			) : false;
		}
		if ( 'global' === $s['auth_type'] && empty( $s['cloudflare_email'] ) ) {
			return $detailed ? array(
				'success' => false,
				'error'   => 'Falta email para Global API Key',
			) : false;
		}

		if ( empty( $s['dns_records_cache'] ) ) {
			$this->persist_dns_cache( $this->fetch_dns_records() );
			$s = $this->get_settings(); }
		$existing = null;
		foreach ( (array) $s['dns_records_cache'] as $r ) {
			if ( ! empty( $r['id'] ) && $r['id'] === $record_id ) {
				$existing = $r;
				break; }
		}
		if ( ! $existing ) {
			$this->persist_dns_cache( $this->fetch_dns_records() );
			$s = $this->get_settings();
			foreach ( (array) $s['dns_records_cache'] as $r ) {
				if ( ! empty( $r['id'] ) && $r['id'] === $record_id ) {
					$existing = $r;
					break; }
			}
			if ( ! $existing ) {
				return $detailed ? array(
					'success' => false,
					'error'   => 'Registro no encontrado en caché tras refresco',
				) : false;
			}
		}

		$type = strtoupper( $existing['type'] ?? '' );
		if ( ! in_array( $type, array( 'A', 'AAAA', 'CNAME' ), true ) ) {
			return $detailed ? array(
				'success' => false,
				'error'   => "Tipo $type no admite Proxy",
				'record'  => $existing,
			) : false;
		}
		if ( array_key_exists( 'proxied', $existing ) && (bool) $existing['proxied'] === (bool) $proxied_on ) {
			return $detailed ? array(
				'success' => true,
				'skipped' => true,
				'record'  => $existing,
			) : true;
		}

		$headers = $this->api_headers( $s );
		$url     = 'https://api.cloudflare.com/client/v4/zones/' . rawurlencode( $s['cloudflare_zone_id'] ) . '/dns_records/' . rawurlencode( $record_id );
		$ttl     = intval( $existing['ttl'] ?? 1 );
		if ( $proxied_on ) {
			$ttl = 1;
		}
		$payload = array(
			'type'    => $type ? $type : 'A',
			'name'    => $existing['name'] ?? '',
			'content' => $existing['content'] ?? '',
			'ttl'     => $ttl,
			'proxied' => (bool) $proxied_on,
		);

		$r = wp_remote_request(
			$url,
			array(
				'method'  => 'PUT',
				'headers' => $headers,
				'timeout' => 30,
				'body'    => wp_json_encode( $payload ),
			)
		);
		if ( is_wp_error( $r ) ) {
			return $detailed ? array(
				'success' => false,
				'error'   => $r->get_error_message(),
				'record'  => $existing,
			) : false;
		}

		$code = wp_remote_retrieve_response_code( $r );
		$body = wp_remote_retrieve_body( $r );
		$json = json_decode( $body, true );
		if ( 200 !== $code || ! is_array( $json ) || empty( $json['success'] ) ) {
			$err = 'Error Cloudflare';
			if ( is_array( $json ) && ! empty( $json['errors'][0]['message'] ) ) {
				$err .= ': ' . $json['errors'][0]['message'];
			} elseif ( 200 !== $code ) {
				$err .= ' (HTTP ' . $code . ')';
			}
			return $detailed ? array(
				'success'  => false,
				'error'    => $err,
				'record'   => $existing,
				'response' => $json,
			) : false;
		}

		foreach ( $s['dns_records_cache'] as &$rr ) {
			if ( ! empty( $rr['id'] ) && $rr['id'] === $record_id ) {
				$rr['proxied'] = (bool) $proxied_on;
				break; }
		}
		$this->persist_dns_cache( $s['dns_records_cache'] );
		return $detailed ? array(
			'success' => true,
			'record'  => $existing,
		) : true;
	}

	/* ================== Capa de caché ================== */

	/**
	 * Save DNS records to the persistent settings cache.
	 *
	 * @param array $records DNS records to cache.
	 */
	private function persist_dns_cache( array $records ) {
		$s                        = $this->get_settings();
		$s['dns_records_cache']   = $records;
		$s['dns_cache_last_sync'] = current_time( 'mysql' );
		$ok                       = $this->save_settings( $s );
		$this->log( 'Persistencia cache DNS: ' . ( $ok ? 'OK' : 'SIN CAMBIOS' ) . ' (' . count( $records ) . ' registros).' );
	}

	/* ================== Lógica automática por JSON ================== */

	/** Check football block status and toggle Cloudflare proxy accordingly. */
	public function check_football_and_manage_cloudflare() {
		$settings           = $this->get_settings();
		$calc               = $this->compute_statuses_from_json();
		$general            = $calc['general'];
		$domain             = $calc['domain'];
		$blocked_domain_ips = $calc['blocked_domain_ips'] ?? array();
		$stored_blocked     = isset( $settings['bypass_blocked_ips'] ) && is_array( $settings['bypass_blocked_ips'] ) ? $settings['bypass_blocked_ips'] : array();
		$now_mysql          = current_time( 'mysql' );
		$now_ts             = time();
		$prev_active        = ! empty( $settings['bypass_active'] );
		$last_change        = isset( $settings['bypass_last_change'] ) ? intval( $settings['bypass_last_change'] ) : 0;
		$cooldown_minutes   = isset( $settings['bypass_check_cooldown'] ) ? intval( $settings['bypass_check_cooldown'] ) : 60;
		if ( $cooldown_minutes < 5 ) {
			$cooldown_minutes = 5;
		}
		if ( $cooldown_minutes > 1440 ) {
			$cooldown_minutes = 1440;
		}
		$cooldown_seconds = $cooldown_minutes * 60;

		$should_disable = ( 'SÍ' === $domain );
		$reason         = $should_disable ? 'domain_blocked' : 'domain_clear';

		// MODIFICACIÓN: Override - forzar OFF cuando General=SI aunque dominio no esté bloqueado.
		if ( ! $should_disable && ! empty( $settings['force_proxy_off_override'] ) && 'SÍ' === $general ) {
			$should_disable = true;
			$reason         = 'override_general_football';
		}

		$cooldown_waiting   = false;
		$cooldown_remaining = 0;
		$still_waiting_ips  = array();

		if ( ! $should_disable && $prev_active ) {
			$still_waiting_ips = array_intersect( $stored_blocked, $blocked_domain_ips );
			if ( ! empty( $still_waiting_ips ) ) {
				$should_disable = true;
				$reason         = 'waiting_previous_ips';
			} elseif ( $last_change && ( $now_ts - $last_change ) < $cooldown_seconds ) {
				$should_disable     = true;
				$reason             = 'cooldown';
				$cooldown_waiting   = true;
				$cooldown_remaining = $cooldown_seconds - ( $now_ts - $last_change );
			}
		}

		$desired_proxied = ! $should_disable;

		$updated          = 0;
		$detailed_results = array();
		if ( ! empty( $settings['selected_records'] ) ) {
			$this->persist_dns_cache( $this->fetch_dns_records() );
			foreach ( $settings['selected_records'] as $rid ) {
				$res = $this->update_record_proxy_status( $rid, $desired_proxied, true );
				if ( is_array( $res ) && ! empty( $res['success'] ) ) {
					if ( empty( $res['skipped'] ) ) {
						++$updated;
					}
					$detailed_results[ $rid ] = $res;
				}
			}
		}

		$settings['last_check']          = $now_mysql;
		$settings['last_status_general'] = ( 'SÍ' === $general ) ? 'SI' : 'NO';
		$settings['last_status_domain']  = ( 'SÍ' === $domain ) ? 'SI' : 'NO';
		$settings['last_update']         = $calc['last_update'] ?? $settings['last_update'];

		if ( $should_disable ) {
			if ( ! $prev_active ) {
				$settings['bypass_last_change'] = $now_ts; }
			$settings['bypass_active']      = 1;
			$settings['bypass_blocked_ips'] = ! empty( $blocked_domain_ips ) ? $blocked_domain_ips : $stored_blocked;
		} else {
			if ( $prev_active ) {
				$settings['bypass_last_change'] = $now_ts; }
			$settings['bypass_active']      = 0;
			$settings['bypass_blocked_ips'] = array();
		}

		$this->save_settings( $settings );
		$this->log( "Auto-check: general={$settings['last_status_general']} domain={$settings['last_status_domain']} updated=$updated" );

		$changes = array();
		if ( ! empty( $settings['selected_records'] ) ) {
			foreach ( $settings['selected_records'] as $rid ) {
				$changes[] = $this->summarize_record_change( $rid, $desired_proxied, $detailed_results[ $rid ] ?? null );
			}
		}

		$log_context = array(
			'general'                    => $settings['last_status_general'],
			'domain'                     => $settings['last_status_domain'],
			'registros_seleccionados'    => count( $settings['selected_records'] ?? array() ),
			'bypass_activo'              => $settings['bypass_active'],
			'cooldown_minutos'           => $cooldown_minutes,
			'motivo'                     => $reason,
			'bypass_ultima_modificacion' => $settings['bypass_last_change'] ?? 0,
			'override_activado'          => ! empty( $settings['force_proxy_off_override'] ) ? 1 : 0,
		);
		if ( $should_disable ) {
			if ( 'domain_blocked' === $reason ) {
				$log_context['accion'] = 'Proxy OFF (dominio bloqueado)';
			} elseif ( 'override_general_football' === $reason ) {
				$log_context['accion'] = 'Proxy OFF (OVERRIDE: General=SI, fútbol detectado)';
			} elseif ( 'waiting_previous_ips' === $reason ) {
				$log_context['accion'] = 'Proxy OFF (esperando desbloqueo de IPs anteriores)';
			} elseif ( 'cooldown' === $reason ) {
				$log_context['accion'] = 'Proxy OFF (en periodo de enfriamiento)';
			} else {
				$log_context['accion'] = 'Proxy OFF';
			}
		} else {
			$log_context['accion'] = 'Proxy ON (dominio sin bloqueo)';
		}
		if ( ! empty( $settings['bypass_blocked_ips'] ) ) {
			$log_context['ips_bloqueadas'] = $settings['bypass_blocked_ips'];
		}
		if ( $cooldown_waiting && $cooldown_remaining > 0 ) {
			$log_context['cooldown_restante_seg'] = $cooldown_remaining;
			$log_context['cooldown_restante_min'] = max( 1, ceil( $cooldown_remaining / 60 ) );
		}
		if ( ! empty( $still_waiting_ips ) ) {
			$log_context['ips_pendientes'] = array_values( $still_waiting_ips );
		}
		if ( $updated > 0 ) {
			$log_context['cambios'] = 'Se aplicaron ' . $updated . ' cambios de proxy.';
		} else {
			$log_context['cambios'] = 'Sin cambios; estado deseado ya aplicado.';
		}
		if ( ! empty( $changes ) ) {
			$log_context['detalle'] = $changes;
		}

		$this->log_event( 'cron', 'Auto-check ejecutado', $log_context );
	}

	/**
	 * Build a summary array describing the proxy change for a single record.
	 *
	 * @param string     $record_id       Cloudflare DNS record ID.
	 * @param bool       $desired_proxied Desired proxy state.
	 * @param array|null $result          Result from update_record_proxy_status.
	 * @return array Summary of the change.
	 */
	private function summarize_record_change( $record_id, $desired_proxied, $result = null ) {
		$s          = $this->get_settings();
		$info       = array( 'id' => $record_id );
		$record_data = null;
		if ( is_array( $result ) && isset( $result['record'] ) ) {
			$record_data     = $result['record'];
			$info['accion'] = empty( $result['skipped'] ) ? 'actualizado' : 'sin cambio';
			if ( ! empty( $result['error'] ) ) {
				$info['accion'] = 'error';
			}
		}
		if ( ! $record_data ) {
			foreach ( (array) $s['dns_records_cache'] as $r ) {
				if ( ! empty( $r['id'] ) && $r['id'] === $record_id ) {
					$record_data = $r;
					break;
				}
			}
		}
		if ( $record_data ) {
			$info['name']              = $record_data['name'] ?? '';
			$info['tipo']              = $record_data['type'] ?? '';
			$info['nuevo_estado']      = $desired_proxied ? 'ON' : 'OFF';
			$current                   = isset( $record_data['proxied'] ) ? ( $record_data['proxied'] ? 'ON' : 'OFF' ) : 'desconocido';
			$info['estado_resultante'] = $current;
			if ( ! isset( $info['accion'] ) ) {
				$info['accion'] = ( $current === $info['nuevo_estado'] ) ? 'sin cambio' : 'actualizado';
			}
		} else {
			$info['accion'] = 'registro no encontrado';
		}
		return $info;
	}

	/* ================== JSON bloqueos ================== */

	/**
	 * Compute general and domain block statuses from the remote JSON data.
	 *
	 * @param bool $force_refresh_ips Whether to force a DNS resolution refresh.
	 * @return array Status data with general, domain, IPs, and timestamps.
	 */
	public function compute_statuses_from_json( $force_refresh_ips = false ) {
		$domain = $this->get_site_domain();
		$data   = $this->fetch_status_json();
		if ( null === $data ) {
			return array(
				'general'            => 'NO',
				'domain'             => 'NO',
				'fresh'              => false,
				'domain_ips'         => array(),
				'blocked_domain_ips' => array(),
				'last_update'        => '',
			); }

		$map             = $data['ip_map'] ?? array();
		$last_update_str = $data['last_update'] ?? '';
		$general_blocked = false;
		foreach ( $map as $ip => $blocked ) {
			if ( true === $blocked ) {
				$general_blocked = true;
				break; }
		}

		$resolved_ips       = $this->resolve_domain_ips( $domain, $force_refresh_ips );
		$blocked_domain_ips = array();
		$domain_blocked     = false;
		foreach ( $resolved_ips as $ip ) {
			if ( isset( $map[ $ip ] ) && true === $map[ $ip ] ) {
				$domain_blocked       = true;
				$blocked_domain_ips[] = $ip;
			}
		}

		return array(
			'general'            => $general_blocked ? 'SÍ' : 'NO',
			'domain'             => $domain_blocked ? 'SÍ' : 'NO',
			'fresh'              => $data['fresh'] ?? false,
			'domain_ips'         => $resolved_ips,
			'blocked_domain_ips' => $blocked_domain_ips,
			'last_update'        => $last_update_str,
		);
	}
	/** Return the current site domain from home_url. */
	private function get_site_domain() {
		$home = home_url( '/' );
		$host = wp_parse_url( $home, PHP_URL_HOST );
		if ( $host ) {
			return $host;
		}
		// Fallback to HTTP_HOST only if home_url parsing fails.
		return isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
	}
	/**
	 * Resolve the A and AAAA records for a domain, with transient caching.
	 *
	 * @param string $domain Domain name to resolve.
	 * @param bool   $force  Whether to bypass the transient cache.
	 * @return array Resolved IP addresses.
	 */
	private function resolve_domain_ips( $domain, $force = false ) {
		$cache_key = 'cfbcolorvivo_domain_ips_cache';
		$cached    = get_transient( $cache_key );
		if ( ! $force && is_array( $cached ) && isset( $cached['domain'] ) && $cached['domain'] === $domain && isset( $cached['ips'] ) ) {
			return (array) $cached['ips'];
		}

		$ips = array();
		if ( $domain && ! $this->is_local_domain( $domain ) ) {
			$records = dns_get_record( $domain, DNS_A + DNS_AAAA );
			if ( is_array( $records ) ) {
				foreach ( $records as $r ) {
					if ( ! empty( $r['type'] ) && ( 'A' === $r['type'] || 'AAAA' === $r['type'] ) ) {
						$ip = 'A' === $r['type'] ? ( $r['ip'] ?? '' ) : ( $r['ipv6'] ?? '' );
						if ( $ip ) {
							$ips[] = $ip;
						}
					}
				}
			}
		}
		$ips = array_values( array_unique( $ips ) );
		set_transient(
			$cache_key,
			array(
				'domain' => $domain,
				'ips'    => $ips,
			),
			MINUTE_IN_SECONDS
		);
		return $ips;
	}
	/** Search for a local copy of data.json in known candidate paths. */
	private function locate_local_data_json() {
		$upload_base = wp_upload_dir()['basedir'];
		$candidates  = array(
			$upload_base . '/es-football-bypass-for-cloudflare/data.json',
			$upload_base . '/cfbcolorvivo/data.json',
		);
		$candidates = apply_filters( 'cfbcolorvivo_local_data_json_paths', $candidates );
		foreach ( $candidates as $p ) {
			if ( ! is_string( $p ) || '' === $p ) {
				continue;
			}
			if ( file_exists( $p ) && is_readable( $p ) && filesize( $p ) > 0 ) {
				return $p;
			}
		}
		return null;
	}
	/** Fetch and cache the football block status JSON from remote or local. */
	private function fetch_status_json() {
		$uploads_dir = $this->plugin_upload_dir;
		$local_path  = $uploads_dir . '/data.json';
		$wp_fs       = $this->get_wp_filesystem();

		$local_body = null;
		$last_local = null;
		if ( $wp_fs && $wp_fs->exists( $local_path ) && $wp_fs->is_readable( $local_path ) && $wp_fs->size( $local_path ) > 0 ) {
			$local_body = $wp_fs->get_contents( $local_path );
			if ( false !== $local_body ) {
				$json_local = json_decode( $local_body, true );
				if ( is_array( $json_local ) && ! empty( $json_local['lastUpdate'] ) && is_string( $json_local['lastUpdate'] ) ) {
					$last_local = $json_local['lastUpdate'];
				}
			}
		}

		$url         = apply_filters( 'cfbcolorvivo_remote_data_json_url', 'https://hayahora.futbol/estado/data.json' );
		$resp        = wp_remote_get(
			$url,
			array(
				'timeout'     => 25,
				'redirection' => 5,
				'user-agent'  => 'ESFB/1.9.2; ' . home_url( '/' ),
			)
		);
		$remote_ok   = false;
		$remote_body = null;
		$last_remote = null;
		if ( ! is_wp_error( $resp ) && wp_remote_retrieve_response_code( $resp ) === 200 ) {
			$remote_body = wp_remote_retrieve_body( $resp );
			$tmp         = json_decode( $remote_body, true );
			if ( is_array( $tmp ) ) {
				$remote_ok = true;
				if ( ! empty( $tmp['lastUpdate'] ) && is_string( $tmp['lastUpdate'] ) ) {
					$last_remote = $tmp['lastUpdate'];
				}
			}
		}

		$should_write = false;
		if ( $remote_ok ) {
			if ( ! $local_body ) {
				$should_write = true; } elseif ( $last_remote && $last_local ) {
				try {
					$dr = new DateTime( $last_remote );
					$dl = new DateTime( $last_local );
					if ( $dr > $dl ) {
						$should_write = true;
					}
				} catch ( Exception $e ) {
					if ( md5( $remote_body ) !== md5( $local_body ) ) {
						$should_write = true;
					}
				}
				} elseif ( md5( $remote_body ) !== md5( $local_body ) ) {
					$should_write = true;
				}
		}

		if ( $should_write ) {
			if ( ! file_exists( $uploads_dir ) ) {
				wp_mkdir_p( $uploads_dir );
			}
			if ( $wp_fs && is_dir( $uploads_dir ) && wp_is_writable( $uploads_dir ) ) {
				$written = $wp_fs->put_contents( $local_path, $remote_body, FS_CHMOD_FILE );
				if ( false !== $written ) {
					$local_body = $remote_body;
					$last_local = $last_remote;
					$this->log( '[CFB] Local data.json actualizado.' );
				}
			} else {
				$this->log( '[CFB] No se puede escribir en ' . $uploads_dir );
			}
		}

		$body = $local_body ? $local_body : ( $remote_ok ? $remote_body : null );
		if ( ! is_string( $body ) || '' === $body ) {
			return null;
		}

		$json = json_decode( $body, true );
		if ( ! is_array( $json ) ) {
			$this->log( '[CFB] JSON decode failed' );
			return null; }

		$last_update_str = ( ! empty( $json['lastUpdate'] ) && is_string( $json['lastUpdate'] ) ) ? $json['lastUpdate'] : '';
		$fresh           = false;
		$now_ts          = time();
		if ( $last_update_str ) {
			$ts = strtotime( $last_update_str );
			if ( $ts ) {
				$diff = $now_ts - $ts;
				if ( isset( $this->fresh_window ) ) {
					$fresh = ( $diff >= 0 && $diff <= $this->fresh_window ); }
			}
		}

		$map = $this->extract_ip_block_map( $json );
		$this->log( '[CFB] data.json procesado; IPs bloqueadas hoy=' . count( $map ) );
		return array(
			'fresh'       => $fresh,
			'ip_map'      => $map,
			'last_update' => $last_update_str,
		);
	}
	/**
	 * Extract a map of IP addresses to blocked status from the JSON data.
	 *
	 * @param array $json Decoded JSON data from the status endpoint.
	 * @return array Associative array of IP => blocked (bool).
	 */
	private function extract_ip_block_map( $json ) {
		$map = array();
		$ips = null;
		foreach ( array( 'ips', 'ip', 'data', 'results' ) as $k ) {
			if ( isset( $json[ $k ] ) ) {
				$ips = $json[ $k ];
				break; }
		}
		if ( null === $ips ) {
			$all = true;
			if ( is_array( $json ) ) {
				foreach ( $json as $k => $v ) {
					if ( ! filter_var( $k, FILTER_VALIDATE_IP ) ) {
						$all = false;
						break;
					}
				} if ( $all ) {
					$ips = $json;
				}
			}
		}
		if ( ! is_array( $ips ) ) {
			return array();
		}
		if ( $this->is_assoc( $ips ) ) {
			foreach ( $ips as $ip => $val ) {
				if ( ! is_string( $ip ) ) {
					continue;
				}
				if ( is_bool( $val ) || is_int( $val ) || is_string( $val ) ) {
					$b = $this->normalize_bool_like( $val );
					if ( null !== $b ) {
						$map[ $ip ] = $b;
					} continue; }
				if ( is_array( $val ) ) {
					$latest       = null;
					$statechanges = $this->array_value_ci( $val, 'statechanges' );
					if ( is_array( $statechanges ) ) {
						$max_ts = null;
						$st    = null;
						foreach ( $statechanges as $chg ) {
							$ts = null;
							if ( isset( $chg['timestamp'] ) ) {
								$ts = strtotime( (string) $chg['timestamp'] );
							} elseif ( isset( $chg['time'] ) ) {
								$ts = strtotime( (string) $chg['time'] );
							}
							if ( false === $ts ) {
								$ts = null;
							}
							$s = isset( $chg['state'] ) ? $this->normalize_bool_like( $chg['state'] ) : ( isset( $chg['status'] ) ? $this->normalize_bool_like( $chg['status'] ) : null );
							if ( null !== $s && ( null === $max_ts || ( null !== $ts && $ts > $max_ts ) ) ) {
								$max_ts = $ts;
								$st    = $s; }
						}
						if ( null !== $st ) {
							$latest = $st;
						}
					}
					foreach ( array( 'isps', 'providers', 'carriers' ) as $k ) {
						if ( null !== $latest ) {
							break;
						}
						$sub = $this->array_value_ci( $val, $k );
						if ( is_array( $sub ) ) {
							$any = null;
							foreach ( $sub as $isp_val ) {
								if ( ! is_array( $isp_val ) ) {
									continue;
								}
								$statechanges_sub = $this->array_value_ci( $isp_val, 'statechanges' );
								if ( is_array( $statechanges_sub ) ) {
									$max_ts = null;
									$st    = null;
									foreach ( $statechanges_sub as $chg ) {
										$ts = null;
										if ( isset( $chg['timestamp'] ) ) {
											$ts = strtotime( (string) $chg['timestamp'] );
										} elseif ( isset( $chg['time'] ) ) {
											$ts = strtotime( (string) $chg['time'] );
										}
										if ( false === $ts ) {
											$ts = null;
										}
										$s = isset( $chg['state'] ) ? $this->normalize_bool_like( $chg['state'] ) : ( isset( $chg['status'] ) ? $this->normalize_bool_like( $chg['status'] ) : null );
										if ( null !== $s && ( null === $max_ts || ( null !== $ts && $ts > $max_ts ) ) ) {
											$max_ts = $ts;
											$st    = $s; }
									}
									if ( null !== $st ) {
										$any = null === $any ? $st : ( $any || $st );
									}
								} else {
									foreach ( array( 'blocked', 'isBlocked', 'status' ) as $kk ) {
										$v = $this->array_value_ci( $isp_val, $kk );
										if ( null !== $v ) {
											$b = $this->normalize_bool_like( $v );
											if ( null !== $b ) {
												$any = null === $any ? $b : ( $any || $b );
											}
										}
									}
								}
							}
							if ( null !== $any ) {
								$latest = $any;
							}
						}
					}
					if ( null !== $latest ) {
						$map[ $ip ] = (bool) $latest;
					}
					foreach ( array( 'blocked', 'isBlocked', 'status' ) as $kk ) {
						$v = $this->array_value_ci( $val, $kk );
						if ( null !== $v ) {
							$b = $this->normalize_bool_like( $v );
							if ( null !== $b ) {
								$map[ $ip ] = $b;
								continue 2; }
						}
					}
				}
			}
		} else {
			foreach ( $ips as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				$ip = (string) ( $entry['ip'] ?? '' );
				if ( ! $ip ) {
					continue;
				}
				$b = null;
				foreach ( array( 'blocked', 'isBlocked', 'status' ) as $k ) {
					$v = $this->array_value_ci( $entry, $k );
					if ( null !== $v ) {
						$b = $this->normalize_bool_like( $v );
						if ( null !== $b ) {
							break;
						}
					}
				}
				if ( null === $b ) {
					$statechanges = $this->array_value_ci( $entry, 'statechanges' );
					if ( is_array( $statechanges ) ) {
						$max_ts = null;
						$st    = null;
						foreach ( $statechanges as $chg ) {
							$ts = null;
							if ( isset( $chg['timestamp'] ) ) {
								$ts = strtotime( (string) $chg['timestamp'] );
							} elseif ( isset( $chg['time'] ) ) {
								$ts = strtotime( (string) $chg['time'] );
							}
							if ( false === $ts ) {
								$ts = null;
							}
							$s = isset( $chg['state'] ) ? $this->normalize_bool_like( $chg['state'] ) : ( isset( $chg['status'] ) ? $this->normalize_bool_like( $chg['status'] ) : null );
							if ( null !== $s && ( null === $max_ts || ( null !== $ts && $ts > $max_ts ) ) ) {
								$max_ts = $ts;
								$st    = $s; }
						}
						if ( null !== $st ) {
							$b = $st;
						}
					}
				}
				if ( null !== $b ) {
					$map[ $ip ] = (bool) $b;
				}
			}
		}
		return $map;
	}

	/* ================== AJAX ================== */

	/** Persist the selected DNS record IDs from an AJAX request. */
	private function persist_selected_from_ajax() {
		$s = $this->get_settings();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified in the calling AJAX handler
		$sel = isset( $_POST['selected'] ) ? array_map( 'sanitize_text_field', wp_unslash( (array) $_POST['selected'] ) ) : array();
		$current_records = isset( $s['selected_records'] ) ? $s['selected_records'] : array();
		if ( $sel !== $current_records ) {
			$s['selected_records'] = $sel;
			$this->save_settings( $s );
			$this->log( 'Seleccion de registros persistida: ' . count( $sel ) . ' ids.' );
		}
		return $sel;
	}

	/** AJAX handler: test Cloudflare connection and refresh DNS cache. */
	public function ajax_test_connection() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Permiso denegado',
					'log'     => array(),
				)
			);
		}
		check_ajax_referer( 'cfbcolorvivo_nonce' );

		$s           = $this->get_settings();
		$log         = array();
		$auth_labels = array(
			'global'        => 'Global API Key',
			'token'         => 'Token de usuario',
			'account_token' => 'Token de cuenta',
		);
		$this->trace( $log, 'Auth: ' . ( $auth_labels[ $s['auth_type'] ] ?? $s['auth_type'] ) . ' | Email: ' . ( 'global' === $s['auth_type'] ? $s['cloudflare_email'] : '—' ) . ( 'account_token' === $s['auth_type'] ? ' | Account: ' . $this->mask( $s['cloudflare_account_id'] ?? '' ) : '' ) );
		$this->trace( $log, 'Zone ID: ' . $this->mask( $s['cloudflare_zone_id'] ) );

		$headers = $this->api_headers( $s );

		if ( 'account_token' === $s['auth_type'] ) {
			if ( empty( $s['cloudflare_account_id'] ) ) {
				wp_send_json_error(
					array(
						'message' => 'Falta Account ID para token de cuenta.',
						'log'     => $log,
					)
				);
			}
			$url = 'https://api.cloudflare.com/client/v4/accounts/' . rawurlencode( $s['cloudflare_account_id'] ) . '/tokens/verify';
			$this->trace( $log, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				wp_send_json_error(
					array(
						'message' => 'Error verificando token de cuenta: ' . $r->get_error_message(),
						'log'     => $log,
					)
				);
			}
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$json  = json_decode( $body, true );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			$this->trace( $log, 'HTTP ' . $code . ' verify=' . ( is_array( $json ) && ! empty( $json['success'] ) ? 'true' : 'false' ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				wp_send_json_error(
					array(
						'message' => 'Token de cuenta inválido o sin permisos (verify).',
						'log'     => $log,
						'http'    => $code,
						'raw'     => substr( (string) $body, 0, 800 ),
					)
				);
			}
		} elseif ( 'token' === $s['auth_type'] ) {
			$url = 'https://api.cloudflare.com/client/v4/user/tokens/verify';
			$this->trace( $log, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				wp_send_json_error(
					array(
						'message' => 'Error verificando token: ' . $r->get_error_message(),
						'log'     => $log,
					)
				);
			}
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$json  = json_decode( $body, true );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			$this->trace( $log, 'HTTP ' . $code . ' verify=' . ( is_array( $json ) && ! empty( $json['success'] ) ? 'true' : 'false' ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				wp_send_json_error(
					array(
						'message' => 'Token inválido o sin permisos (verify).',
						'log'     => $log,
						'http'    => $code,
						'raw'     => substr( (string) $body, 0, 800 ),
					)
				);
			}
		} else {
			$url = 'https://api.cloudflare.com/client/v4/user';
			$this->trace( $log, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				wp_send_json_error(
					array(
						'message' => 'Error verificando usuario: ' . $r->get_error_message(),
						'log'     => $log,
					)
				);
			}
			$code  = wp_remote_retrieve_response_code( $r );
			$body  = wp_remote_retrieve_body( $r );
			$json  = json_decode( $body, true );
			$cf_ray = wp_remote_retrieve_header( $r, 'cf-ray' );
			$this->trace( $log, 'HTTP ' . $code . ' user=' . ( is_array( $json ) && ! empty( $json['success'] ) ? 'true' : 'false' ) . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				wp_send_json_error(
					array(
						'message' => 'Autenticación fallida con Global API Key/Email.',
						'log'     => $log,
						'http'    => $code,
						'raw'     => substr( (string) $body, 0, 800 ),
					)
				);
			}
		}

		if ( ! empty( $s['cloudflare_zone_id'] ) ) {
			$url = 'https://api.cloudflare.com/client/v4/zones/' . rawurlencode( $s['cloudflare_zone_id'] );
			$this->trace( $log, 'GET ' . $url );
			$r = wp_remote_get(
				$url,
				array(
					'headers' => $headers,
					'timeout' => 20,
				)
			);
			if ( is_wp_error( $r ) ) {
				wp_send_json_error(
					array(
						'message' => 'Error comprobando zona: ' . $r->get_error_message(),
						'log'     => $log,
					)
				);
			}
			$code      = wp_remote_retrieve_response_code( $r );
			$body      = wp_remote_retrieve_body( $r );
			$json      = json_decode( $body, true );
			$cf_ray     = wp_remote_retrieve_header( $r, 'cf-ray' );
			$zone_name = is_array( $json ) && ! empty( $json['result']['name'] ) ? $json['result']['name'] : '?';
			$this->trace( $log, 'HTTP ' . $code . ' zone=' . ( is_array( $json ) && ! empty( $json['success'] ) ? 'true' : 'false' ) . ' name=' . $zone_name . ' cf-ray=' . ( $cf_ray ? $cf_ray : '—' ) );
			if ( 200 !== $code || empty( $json['success'] ) ) {
				wp_send_json_error(
					array(
						'message' => 'No se pudo acceder a la zona (ID incorrecto o sin permisos).',
						'log'     => $log,
						'http'    => $code,
						'raw'     => substr( (string) $body, 0, 800 ),
					)
				);
			}
			$site_domain = $this->get_site_domain();
			if ( ! $this->domain_matches_zone( $site_domain, $zone_name ) ) {
				wp_send_json_error(
					array(
						'message' => 'El Zone ID no corresponde con el dominio actual (' . $site_domain . ').',
						'log'     => $log,
					)
				);
			}
		} else {
			wp_send_json_error(
				array(
					'message' => 'Zone ID vacío.',
					'log'     => $log,
				)
			);
		}

		$this->trace( $log, 'Obteniendo registros DNS (A, AAAA, CNAME)…' );
		$records = $this->fetch_dns_records( array( 'A', 'AAAA', 'CNAME' ), $log );
		$count   = count( $records );
		$this->trace( $log, 'Total registros validos: ' . $count );

		$sample = array_slice( $records, 0, 10 );
		foreach ( $sample as $rr ) {
			$this->trace(
				$log,
				sprintf(
					' - %s %s (%s) proxied=%s ttl=%s id=%s',
					$rr['type'],
					$rr['name'],
					$rr['content'],
					( null === $rr['proxied'] ? '—' : ( $rr['proxied'] ? 'ON' : 'OFF' ) ),
					$rr['ttl'],
					$this->mask( $rr['id'] )
				)
			);
		}
		if ( $count > 10 ) {
			$this->trace( $log, ' ... +' . ( $count - 10 ) . ' mas' );
		}

		if ( empty( $records ) ) {
			wp_send_json_error(
				array(
					'message' => 'No se obtuvieron registros (permiso DNS:Read?).',
					'log'     => $log,
				)
			);
		}

		$this->persist_dns_cache( $records );
		$this->trace( $log, 'Cache actualizado y guardado.' );

		$sel = $this->persist_selected_from_ajax();

		$s2 = $this->get_settings();
		ob_start();
		$this->echo_dns_table( $s2['dns_records_cache'], $sel ? $sel : ( $s2['selected_records'] ?? array() ) );
		$html = ob_get_clean();

		$this->log_event(
			'manual',
			'Test de conexión ejecutado',
			array(
				'usuario'            => $this->current_user_label(),
				'registros_en_cache' => count( $s2['dns_records_cache'] ?? array() ),
				'seleccionados'      => count( $s2['selected_records'] ?? array() ),
			)
		);

		wp_send_json_success(
			array(
				'html' => $html,
				'log'  => $log,
			)
		);
	}

	/** AJAX handler: return current block status for the summary panel. */
	public function ajax_get_status() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Permiso denegado',
					'log'     => array(),
				)
			);
		}
		check_ajax_referer( 'cfbcolorvivo_nonce' );
		$calc = $this->compute_statuses_from_json();
		wp_send_json_success(
			array(
				'general'     => $calc['general'],
				'domain'      => $calc['domain'],
				'ips'         => $calc['domain_ips'],
				'last_update' => $calc['last_update'],
			)
		);
	}

	/** AJAX handler: run a manual football block check. */
	public function ajax_manual_check() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Permiso denegado',
					'log'     => array(),
				)
			);
		}
		check_ajax_referer( 'cfbcolorvivo_nonce' );
		$log = array();
		$this->trace( $log, 'Ejecucion manual: comprobando JSON de IPs y aplicando politica…' );
		$this->persist_selected_from_ajax();
		$this->check_football_and_manage_cloudflare();
		$s = $this->get_settings();
		$this->log_event(
			'manual',
			'Comprobación manual ejecutada',
			array(
				'usuario' => $this->current_user_label(),
				'general' => $s['last_status_general'] ?? 'NO',
				'dominio' => $s['last_status_domain'] ?? 'NO',
			)
		);
		wp_send_json_success(
			array(
				'last'        => $s['last_check'],
				'general'     => $s['last_status_general'],
				'domain'      => $s['last_status_domain'],
				'last_update' => $s['last_update'] ?? '',
				'log'         => $log,
			)
		);
	}

	/** AJAX handler: force proxy OFF (DNS Only) on selected records. */
	public function ajax_force_deactivate() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Permiso denegado',
					'log'     => array(),
				)
			);
		}
		check_ajax_referer( 'cfbcolorvivo_nonce' );
		$log = array();
		$this->trace( $log, 'Forzar OFF: refrescando estado real desde Cloudflare…' );

		$sel = $this->persist_selected_from_ajax();
		if ( empty( $sel ) ) {
			wp_send_json_error(
				array(
					'message' => 'No hay registros seleccionados.',
					'log'     => $log,
				)
			);
		}

		$before = $this->fetch_dns_records( array( 'A', 'AAAA', 'CNAME' ), $log );
		if ( ! empty( $before ) ) {
			$this->persist_dns_cache( $before );
		}
		$ok    = 0;
		$fail  = 0;
		$lines = array();
		foreach ( $sel as $rid ) {
			$res = $this->update_record_proxy_status( $rid, false, true );
			if ( is_array( $res ) && ! empty( $res['success'] ) ) {
				if ( ! empty( $res['skipped'] ) ) {
					$lines[] = 'SKIP: ' . ( $res['record']['name'] ?? $rid ) . ' (ya OFF)';
				} else {
					++$ok;
					$lines[] = 'OK: ' . ( $res['record']['name'] ?? $rid ) . ' -> OFF'; }
			} else {
				++$fail;
				$lines[] = 'ERR: ' . ( ( $res['record']['name'] ?? $rid ) ) . ' ' . ( is_array( $res ) && ! empty( $res['error'] ) ? $res['error'] : '' );
			}
		}
		$after = $this->fetch_dns_records( array( 'A', 'AAAA', 'CNAME' ), $log );
		if ( ! empty( $after ) ) {
			$this->persist_dns_cache( $after );
		}

		$s2 = $this->get_settings();
		ob_start();
		$this->echo_dns_table( $s2['dns_records_cache'], $sel );
		$html = ob_get_clean();
		$msg  = "Proxy OFF en $ok registros" . ( $fail ? "; fallidos: $fail" : '' ) . '.';
		$this->log_event(
			'manual',
			'Forzar Proxy OFF',
			array(
				'usuario'    => $this->current_user_label(),
				'procesados' => count( $sel ),
				'ok'         => $ok,
				'errores'    => $fail,
			)
		);
		wp_send_json_success(
			array(
				'message' => $msg,
				'report'  => implode( "\n", $lines ),
				'html'    => $html,
				'log'     => array_merge( $log, $lines, array( $msg ) ),
			)
		);
	}

	/** AJAX handler: force proxy ON (CDN) on selected records. */
	public function ajax_force_activate() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Permiso denegado',
					'log'     => array(),
				)
			);
		}
		check_ajax_referer( 'cfbcolorvivo_nonce' );
		$log = array();
		$this->trace( $log, 'Forzar ON: refrescando estado real desde Cloudflare…' );

		$sel = $this->persist_selected_from_ajax();
		if ( empty( $sel ) ) {
			wp_send_json_error(
				array(
					'message' => 'No hay registros seleccionados.',
					'log'     => $log,
				)
			);
		}

		$before = $this->fetch_dns_records( array( 'A', 'AAAA', 'CNAME' ), $log );
		if ( ! empty( $before ) ) {
			$this->persist_dns_cache( $before );
		}
		$ok    = 0;
		$fail  = 0;
		$lines = array();
		foreach ( $sel as $rid ) {
			$res = $this->update_record_proxy_status( $rid, true, true );
			if ( is_array( $res ) && ! empty( $res['success'] ) ) {
				if ( ! empty( $res['skipped'] ) ) {
					$lines[] = 'SKIP: ' . ( $res['record']['name'] ?? $rid ) . ' (ya ON)';
				} else {
					++$ok;
					$lines[] = 'OK: ' . ( $res['record']['name'] ?? $rid ) . ' -> ON'; }
			} else {
				++$fail;
				$lines[] = 'ERR: ' . ( ( $res['record']['name'] ?? $rid ) ) . ' ' . ( is_array( $res ) && ! empty( $res['error'] ) ? $res['error'] : '' );
			}
		}
		$after = $this->fetch_dns_records( array( 'A', 'AAAA', 'CNAME' ), $log );
		if ( ! empty( $after ) ) {
			$this->persist_dns_cache( $after );
		}

		$s2 = $this->get_settings();
		ob_start();
		$this->echo_dns_table( $s2['dns_records_cache'], $sel );
		$html = ob_get_clean();
		$msg  = "Proxy ON en $ok registros" . ( $fail ? "; fallidos: $fail" : '' ) . '.';
		$this->log_event(
			'manual',
			'Forzar Proxy ON',
			array(
				'usuario'    => $this->current_user_label(),
				'procesados' => count( $sel ),
				'ok'         => $ok,
				'errores'    => $fail,
			)
		);
		wp_send_json_success(
			array(
				'message' => $msg,
				'report'  => implode( "\n", $lines ),
				'html'    => $html,
				'log'     => array_merge( $log, $lines, array( $msg ) ),
			)
		);
	}

	/** AJAX handler: return WP-Cron diagnostic information. */
	public function ajax_cron_diagnostics() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => 'Permiso denegado',
					'log'     => array(),
				)
			);
		}
		check_ajax_referer( 'cfbcolorvivo_nonce' );
		$s         = $this->get_settings();
		$mins      = max( 5, min( 60, intval( $s['check_interval'] ) ) );
		$next_ts    = wp_next_scheduled( $this->cron_hook );
		$next      = $next_ts ? date_i18n( 'Y-m-d H:i:s', $next_ts ) : '—';
		$now_ts     = time();
		$cron_state = 'OK';
		if ( $next_ts && $next_ts <= $now_ts - MINUTE_IN_SECONDS ) {
			$cron_state = 'ATRASADO (WP-Cron no ha podido ejecutarse)';
		}
		$last_check_val    = $s['last_check'] ? $s['last_check'] : '—';
		$general_val       = $s['last_status_general'] ? $s['last_status_general'] : '—';
		$domain_val        = $s['last_status_domain'] ? $s['last_status_domain'] : '—';
		$override_val      = ! empty( $s['force_proxy_off_override'] ) ? 'SI' : 'NO';
		$last_update_val   = ! empty( $s['last_update'] ) ? $s['last_update'] : '—';
		$last_sync_val     = ! empty( $s['dns_cache_last_sync'] ) ? $s['dns_cache_last_sync'] : '—';
		$msg = "Cron hook: {$this->cron_hook}\nIntervalo: {$mins} min\nSiguiente ejecucion: {$next}\nEstado cron: {$cron_state}\nUltima comprobacion: " . $last_check_val . "\nGeneral (bloqueos IPs): " . $general_val . "\nDominio bloqueado: " . $domain_val . "\nOverride activo: " . $override_val . "\nUltima actualizacion (JSON de IPs): " . $last_update_val . "\nRegistros sincronizados: " . $last_sync_val;
		wp_send_json_success( array( 'msg' => $msg ) );
	}
}

new Cfbcolorvivo_Cloudflare_Football_Bypass();
