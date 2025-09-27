<?php
/**
 * Plugin Name: CF Football Bypass (Cloudflare)
 * Plugin URI: https://carrero.es
 * Description: Opera con Cloudflare para alternar Proxy (ON/CDN) y DNS Only (OFF) según bloqueos, con caché persistente de registros y acciones AJAX. UI separada: Operación y Configuración.
 * Version: 1.5.4
 * Author: David Carrero (@carrero)
 * License: GPL v2 or later
 */

if (!defined('ABSPATH')) exit;

final class CloudflareFootballBypass
{
    private $option_name    = 'cfb_settings';
    private $cron_hook      = 'cfb_check_football_status';
    private $fresh_window   = 240 * 60; // 4h (informativo)
    private $log_file_path;
    private $suspend_reschedule = false;

    public function __construct()
    {
        $this->log_file_path = plugin_dir_path(__FILE__).'cfb-actions.log';
        add_action('updated_option', [$this, 'handle_option_updated'], 10, 3);

        add_action('admin_menu', [$this, 'register_menus']);
        add_action('admin_init', [$this, 'settings_init']);
        add_action('admin_notices', [$this, 'settings_save_notices']);

        add_action($this->cron_hook, [$this, 'check_football_and_manage_cloudflare']);
        add_filter('cron_schedules', [$this, 'add_custom_cron_interval']);

        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);

        add_action('wp_ajax_cfb_test_connection',  [$this, 'ajax_test_connection']);
        add_action('wp_ajax_cfb_manual_check',     [$this, 'ajax_manual_check']);
        add_action('wp_ajax_cfb_get_status',       [$this, 'ajax_get_status']);
        add_action('wp_ajax_cfb_force_activate',   [$this, 'ajax_force_activate']);
        add_action('wp_ajax_cfb_force_deactivate', [$this, 'ajax_force_deactivate']);
        add_action('wp_ajax_cfb_cron_diagnostics', [$this, 'ajax_cron_diagnostics']);
        add_action('init', [$this, 'maybe_process_external_cron']);
    }

    /* ================== Utilidades ================== */

    private function to_ascii($s){
        $t = $s;
        if (function_exists('iconv')) {
            $x = @iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$s);
            if ($x!==false) $t = $x;
        }
        $map = [
            '¿'=>'?','¡'=>'!','…'=>'...','—'=>'-','–'=>'-','•'=>'*',
            'á'=>'a','Á'=>'A','é'=>'e','É'=>'E','í'=>'i','Í'=>'I','ó'=>'o','Ó'=>'O','ú'=>'u','Ú'=>'U','ñ'=>'n','Ñ'=>'N','ü'=>'u','Ü'=>'U'
        ];
        return strtr($t, $map);
    }
    private function log($msg){
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $out = is_scalar($msg) ? (string)$msg : wp_json_encode($msg, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
            error_log('[CFB] '.$this->to_ascii($out));
        }
    }
    private function trace(&$bag, $line){
        if (is_array($bag)) $bag[] = $line;  // consola bonita (UTF-8)
        $this->log($line);                   // log ASCII-safe
    }
    private function mask($str, $left=6, $right=4){
        $s = (string)$str; $len = strlen($s);
        if ($len <= $left + $right) return str_repeat('*', max(0,$len));
        return substr($s,0,$left) . str_repeat('*', $len-$left-$right) . substr($s,-$right);
    }
    private function is_assoc($arr){
        if (!is_array($arr)) return false;
        return array_keys($arr) !== range(0, count($arr) - 1);
    }
    private function normalize_bool_like($v){
        if (is_bool($v)) return $v;
        if (is_int($v)) return $v !== 0;
        if (is_string($v)) {
            $vv = strtolower(trim($v));
            if (in_array($vv, ['1','true','yes','si','sí','on','blocked','proxy','cdn'], true)) return true;
            if (in_array($vv, ['0','false','no','off','unblocked'], true)) return false;
        }
        return null;
    }
    private function array_value_ci($array, $key){
        if (!is_array($array)) return null;
        if (array_key_exists($key, $array)) return $array[$key];
        $lk = strtolower($key);
        foreach ($array as $k=>$v){ if (is_string($k) && strtolower($k)===$lk) return $v; }
        return null;
    }
    private function generate_cron_secret(){
        if (function_exists('wp_generate_password')) {
            return wp_generate_password(32, false, false);
        }
        try {
            return bin2hex(random_bytes(16));
        } catch (Exception $e) {
            return md5(uniqid('', true));
        }
    }
    private function get_default_settings($force_new_token=false){
        $secret = $force_new_token ? $this->generate_cron_secret() : '';
        return [
            'cloudflare_email'    => '',
            'cloudflare_api_key'  => '',
            'cloudflare_zone_id'  => '',
            'auth_type'           => 'global',
            'check_interval'      => 15,
            'selected_records'    => [],
            'dns_records_cache'   => [],
            'dns_cache_last_sync' => '',
            'last_check'          => '',
            'last_status_general' => 'NO',
            'last_status_domain'  => 'NO',
            'last_update'         => '',
            'logging_enabled'     => 1,
            'log_retention_days'  => 30,
            'cron_secret'         => $secret,
        ];
    }
    private function clear_logs_file(){
        $path = $this->get_log_file_path();
        if (file_exists($path)) @unlink($path);
    }
    public function handle_option_updated($option, $old, $new){
        if ($option !== $this->option_name) return;
        if ($this->suspend_reschedule) return;
        $old_interval = isset($old['check_interval']) ? intval($old['check_interval']) : null;
        $new_interval = isset($new['check_interval']) ? intval($new['check_interval']) : null;
        if ($old_interval === $new_interval && wp_next_scheduled($this->cron_hook)) {
            return;
        }
        $this->reschedule_cron_after_interval_change();
    }
    private function save_settings(array $settings){
        $this->suspend_reschedule = true;
        $result = update_option($this->option_name, $settings);
        $this->suspend_reschedule = false;
        return $result;
    }
    private function domain_matches_zone($domain, $zone){
        $domain = strtolower(trim((string)$domain));
        $zone   = strtolower(trim((string)$zone));
        if ($domain === '' || $zone === '') return false;
        if ($domain === $zone) return true;
        return substr($domain, -strlen('.'.$zone)) === '.'.$zone;
    }
    private function current_user_label(){
        if (!function_exists('wp_get_current_user')) return 'desconocido';
        $user = wp_get_current_user();
        if ($user && $user->exists()) return $user->user_login.' (#'.$user->ID.')';
        return 'desconocido';
    }
    private function get_log_file_path(){
        return $this->log_file_path;
    }
    private function log_event($type, $message, array $context = []){
        $settings = $this->get_settings();
        if (empty($settings['logging_enabled'])) return;
        $path = $this->get_log_file_path();
        $dir = dirname($path);
        if (!file_exists($dir)) {
            if (!wp_mkdir_p($dir)) {
                $this->log('No se puede crear el directorio de logs: '.$dir);
                return;
            }
        }
        $dir_writable = function_exists('wp_is_writable') ? wp_is_writable($dir) : is_writable($dir);
        if (!$dir_writable) {
            $this->log('Directorio de logs no escribible: '.$dir);
            return;
        }

        $entry = [
            'time'    => current_time('mysql'),
            'type'    => (string)$type,
            'message' => $message,
        ];
        if (!empty($context)) $entry['context'] = $context;
        $line = wp_json_encode($entry, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        if ($line === false) return;
        $line .= "\n";

        $written = @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
        if ($written === false) {
            $this->log('No se pudo escribir en el log de acciones: '.$path);
            return;
        }
        $days = isset($settings['log_retention_days']) ? intval($settings['log_retention_days']) : 30;
        $this->prune_logs($days);
    }
    private function prune_logs($days){
        $days = max(1, intval($days));
        $path = $this->get_log_file_path();
        if (!file_exists($path) || !is_readable($path)) return;
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if (!is_array($lines)) return;
        $cutoff = current_time('timestamp') - ($days * DAY_IN_SECONDS);
        $filtered = [];
        foreach ($lines as $line){
            if ($line === '') continue;
            $keep = true;
            $entry = json_decode($line, true);
            if (is_array($entry) && !empty($entry['time'])){
                $ts = strtotime($entry['time']);
                if ($ts && $ts < $cutoff) {
                    $keep = false;
                }
            }
            if ($keep) $filtered[] = $line;
        }
        if (count($filtered) === count($lines)) return;
        $data = $filtered ? implode("\n", $filtered)."\n" : '';
        @file_put_contents($path, $data, LOCK_EX);
    }
    private function read_log_entries($limit = 200){
        $path = $this->get_log_file_path();
        if (!file_exists($path) || !is_readable($path)) return [];
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) return [];
        $entries = [];
        foreach ($lines as $line){
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                $entry = ['time'=>'','type'=>'info','message'=>$line];
            }
            $entries[] = $entry;
        }
        usort($entries, function($a,$b){
            $ta = isset($a['time']) ? strtotime((string)$a['time']) : 0;
            $tb = isset($b['time']) ? strtotime((string)$b['time']) : 0;
            if ($ta === $tb) return 0;
            return ($ta > $tb) ? -1 : 1;
        });
        if ($limit > 0 && count($entries) > $limit) {
            $entries = array_slice($entries, 0, $limit);
        }
        return $entries;
    }

    public function maybe_process_external_cron(){
        if (!isset($_GET['cfb_cron'])) return;
        $s = $this->get_settings();
        $token = isset($_GET['token']) ? sanitize_text_field(wp_unslash($_GET['token'])) : '';
        if (empty($s['cron_secret']) || $token !== $s['cron_secret']) {
            status_header(403);
            echo 'CFB: token inválido';
            exit;
        }
        $this->log_event('external_cron', 'Cron externo disparado', ['ip'=>$_SERVER['REMOTE_ADDR'] ?? '']);
        $this->check_football_and_manage_cloudflare();
        echo 'CFB cron OK';
        exit;
    }

    /* ================== Normalización / Migración ================== */

    private function normalize_dns_cache($cache_in){
        $out = [];
        if (is_array($cache_in) && $this->is_assoc($cache_in)) $cache_in = array_values($cache_in);
        if (!is_array($cache_in)) return $out;
        foreach ($cache_in as $r) {
            if (!is_array($r)) continue;
            $id   = isset($r['id'])      ? (string)$r['id']      : '';
            $name = isset($r['name'])    ? (string)$r['name']    : '';
            $type = isset($r['type'])    ? strtoupper((string)$r['type']) : '';
            $cont = isset($r['content']) ? (string)$r['content'] : '';
            $prox = null;
            if (array_key_exists('proxied', $r)) $prox = $this->normalize_bool_like($r['proxied']);
            elseif (array_key_exists('proxy',$r)) $prox = $this->normalize_bool_like($r['proxy']);
            elseif (array_key_exists('cdn',$r)) $prox = $this->normalize_bool_like($r['cdn']);
            $ttl = isset($r['ttl']) ? intval($r['ttl']) : 1;
            if ($ttl <= 0) $ttl = 1;
            if ($id && $name && $type && $cont) {
                $out[] = ['id'=>$id,'name'=>$name,'type'=>$type,'content'=>$cont,'proxied'=>$prox,'ttl'=>$ttl];
            }
        }
        return $out;
    }
    private function normalize_settings($opt_in){
        $changed = false;
        $opt = is_array($opt_in) ? $opt_in : [];
        $defaults = $this->get_default_settings();
        foreach ($defaults as $k=>$v){ if (!array_key_exists($k,$opt)) { $opt[$k]=$v; $changed=true; } }

        $auth = in_array($opt['auth_type'], ['global','token'], true) ? $opt['auth_type'] : 'global';
        if ($auth !== $opt['auth_type']) { $opt['auth_type']='global'; $changed=true; }

        $mins = max(5, min(60, intval($opt['check_interval'])));
        if ($mins !== intval($opt['check_interval'])) { $opt['check_interval']=$mins; $changed=true; }

        if (is_string($opt['selected_records'])) { $opt['selected_records'] = array_filter(array_map('trim', explode(',', $opt['selected_records']))); $changed=true; }
        if (!is_array($opt['selected_records'])) { $opt['selected_records']=[]; $changed=true; }
        $sel_norm=[]; foreach ($opt['selected_records'] as $rid){ if (is_scalar($rid)&&$rid!=='') $sel_norm[]=(string)$rid; }
        if ($sel_norm !== $opt['selected_records']) { $opt['selected_records']=$sel_norm; $changed=true; }

        $norm_cache = $this->normalize_dns_cache($opt['dns_records_cache']);
        if ($norm_cache !== $opt['dns_records_cache']) { $opt['dns_records_cache']=$norm_cache; $changed=true; }

        foreach (['last_status_general','last_status_domain'] as $k){
            $v = strtoupper((string)$opt[$k]); if (in_array($v,['SÍ','SI'])) $v='SI'; if (!in_array($v,['SI','NO'])) $v='NO';
            if ($v !== $opt[$k]) { $opt[$k]=$v; $changed=true; }
        }

        $opt['logging_enabled'] = !empty($opt['logging_enabled']) ? 1 : 0;
        $days = isset($opt['log_retention_days']) ? intval($opt['log_retention_days']) : 30;
        if ($days < 1) $days = 1;
        if ($days !== intval($opt['log_retention_days'])) { $opt['log_retention_days']=$days; $changed=true; }
        if (empty($opt['cron_secret']) || !is_string($opt['cron_secret'])) {
            $opt['cron_secret'] = wp_generate_password(32, false, false);
            $changed = true;
        }
        return [$opt,$changed];
    }
    private function get_settings(){
        $raw = get_option($this->option_name, []);
        list($opt,$changed) = $this->normalize_settings($raw);
        if ($changed) { $this->save_settings($opt); $this->log('Configuracion normalizada/migrada.'); }
        return $opt;
    }

    /* ================== Activación / Desactivación ================== */

    public function activate(){
        $s = $this->get_settings();
        if (empty($s['check_interval'])) { $s['check_interval'] = 15; $this->save_settings($s); }
        if (!wp_next_scheduled($this->cron_hook)) {
            $interval = max(5, min(60, intval($s['check_interval'])));
            /* cleanup legacy schedule names */
$next = wp_next_scheduled($this->cron_hook);
while ($next) { wp_unschedule_event($next, $this->cron_hook); $next = wp_next_scheduled($this->cron_hook); }
// schedule with stable slug
wp_schedule_event(time() + 60, 'cf_fb_custom', $this->cron_hook);
}
    }
    public function deactivate(){
        $timestamp = wp_next_scheduled($this->cron_hook);
        if ($timestamp) wp_unschedule_event($timestamp, $this->cron_hook);

        $opt = $this->get_settings();
        if (!empty($opt['selected_records'])) {
            foreach ($opt['selected_records'] as $rid) { $this->update_record_proxy_status($rid, true); }
            $this->log('Desactivado: Proxy restaurado (ON) en registros seleccionados.');
        }
    }

    /* ================== Menús (Operación y Configuración) ================== */

    public function register_menus(){
        add_menu_page(
            'CF Football Bypass',
            'CF Football Bypass',
            'manage_options',
            'cfb-main',
            [$this, 'render_main_page'],
            'dashicons-shield',
            66
        );
        add_submenu_page('cfb-main','Operacion','Operación','manage_options','cfb-main',[$this,'render_main_page']);
        add_submenu_page('cfb-main','Configuracion','Configuración','manage_options','cfb-settings',[$this,'render_settings_page']);
        add_submenu_page('cfb-main','Registros','Logs','manage_options','cfb-logs',[$this,'render_logs_page']);
    }

    /* ================== Settings API ================== */

    public function settings_init(){
        register_setting('cfb_settings_group', $this->option_name, [$this, 'sanitize_settings']);

        add_settings_section('cfb_cloudflare_section', __('Credenciales de Cloudflare','cfb'), '__return_false', 'cfb_settings_page');
        add_settings_field('auth_type', __('Tipo de autenticación','cfb'), [$this,'auth_type_render'], 'cfb_settings_page', 'cfb_cloudflare_section');
        add_settings_field('cloudflare_email', __('Email (sólo Global API Key)','cfb'), [$this,'email_render'], 'cfb_settings_page', 'cfb_cloudflare_section');
        add_settings_field('cloudflare_api_key', __('API Key Global o Token','cfb'), [$this,'api_key_render'], 'cfb_settings_page', 'cfb_cloudflare_section');
        add_settings_field('cloudflare_zone_id', __('Zone ID','cfb'), [$this,'zone_id_render'], 'cfb_settings_page', 'cfb_cloudflare_section');

        add_settings_section('cfb_plugin_section', __('Ajustes del plugin','cfb'), '__return_false', 'cfb_settings_page');
        add_settings_field('check_interval', __('Intervalo de comprobación (minutos)','cfb'), [$this,'check_interval_render'], 'cfb_settings_page', 'cfb_plugin_section');
        add_settings_field('selected_records', __('Registros DNS a gestionar (se cargan en Operación)','cfb'), [$this,'selected_records_hint'], 'cfb_settings_page', 'cfb_plugin_section');
        add_settings_field('logging_enabled', __('Registro de acciones','cfb'), [$this,'logging_enabled_render'], 'cfb_settings_page', 'cfb_plugin_section');
        add_settings_field('log_retention_days', __('Retención de logs (días)','cfb'), [$this,'log_retention_render'], 'cfb_settings_page', 'cfb_plugin_section');
        add_settings_field('cron_secret', __('Token para cron externo','cfb'), [$this,'cron_secret_render'], 'cfb_settings_page', 'cfb_plugin_section');
        add_settings_field('reset_settings', __('Resetear configuración','cfb'), [$this,'reset_settings_render'], 'cfb_settings_page', 'cfb_plugin_section');
    }

    public function sanitize_settings($input){
        $existing = get_option($this->option_name, []);
        $san = [];

        // Campos de credenciales / core
        $san['cloudflare_email']   = isset($input['cloudflare_email'])   ? sanitize_email($input['cloudflare_email'])           : ($existing['cloudflare_email']   ?? '');
        $san['cloudflare_api_key'] = isset($input['cloudflare_api_key']) ? sanitize_text_field($input['cloudflare_api_key'])    : ($existing['cloudflare_api_key'] ?? '');
        $san['cloudflare_zone_id'] = isset($input['cloudflare_zone_id']) ? sanitize_text_field($input['cloudflare_zone_id'])    : ($existing['cloudflare_zone_id'] ?? '');
        $auth = isset($input['auth_type']) ? sanitize_text_field($input['auth_type']) : ($existing['auth_type'] ?? 'global');
        $san['auth_type'] = in_array($auth, ['global','token'], true) ? $auth : 'global';

        $mins_in = isset($input['check_interval']) ? intval($input['check_interval']) : ($existing['check_interval'] ?? 15);
        $san['check_interval'] = max(5, min(60, $mins_in));

        // Si llegan desde AJAX estos campos, respetarlos (no pisar)
        $san['dns_records_cache']   = array_key_exists('dns_records_cache',$input)   ? $input['dns_records_cache']   : ($existing['dns_records_cache']   ?? []);
        $san['selected_records']    = array_key_exists('selected_records',$input)    ? $input['selected_records']    : ($existing['selected_records']    ?? []);

        // Estado persistente
        $san['dns_cache_last_sync'] = array_key_exists('dns_cache_last_sync',$input) ? $input['dns_cache_last_sync'] : ($existing['dns_cache_last_sync'] ?? '');
        $san['last_check']          = array_key_exists('last_check',$input)          ? $input['last_check']          : ($existing['last_check']          ?? '');
        $san['last_status_general'] = array_key_exists('last_status_general',$input) ? $input['last_status_general'] : ($existing['last_status_general'] ?? 'NO');
        $san['last_status_domain']  = array_key_exists('last_status_domain',$input)  ? $input['last_status_domain']  : ($existing['last_status_domain']  ?? 'NO');
        $san['last_update']         = array_key_exists('last_update',$input)         ? $input['last_update']         : ($existing['last_update']         ?? '');
        $san['logging_enabled']     = isset($input['logging_enabled']) ? (int)!empty($input['logging_enabled']) : ($existing['logging_enabled'] ?? 1);
        $san['log_retention_days']  = isset($input['log_retention_days']) ? intval($input['log_retention_days']) : ($existing['log_retention_days'] ?? 30);
        $san['cron_secret']         = isset($input['cron_secret']) ? sanitize_text_field($input['cron_secret']) : ($existing['cron_secret'] ?? '');
        $reset_requested            = !empty($input['reset_settings']);

        // Normaliza estructuras
        list($san,) = $this->normalize_settings($san);

        if ($reset_requested){
            $san = $this->get_default_settings(true);
            $this->clear_logs_file();
            delete_option('cfb_settings_last_trace');
            delete_transient('cfb_settings_notice_ok');
            delete_transient('cfb_settings_notice_err');
            $this->log('Configuración reseteada manualmente.');
        }

        unset($san['reset_settings']);

        // Reprogramar cron si cambia intervalo
        if (!isset($existing['check_interval']) || intval($existing['check_interval']) !== intval($san['check_interval'])) {
            $this->reschedule_cron_after_interval_change();
        }

        // Test sólo si guardas desde la página de ajustes (no AJAX)
        $is_settings_form = !wp_doing_ajax() && isset($_POST['option_page']) && $_POST['option_page']==='cfb_settings_group';
        if ($is_settings_form) {
            $trace = [];
            $ok = $this->quick_settings_test($san, $trace);
            // Guardar último log para la consola de Configuración
            update_option('cfb_settings_last_trace', [
                'ok'    => (bool)$ok,
                'trace' => $trace,
                'ts'    => current_time('mysql')
            ]);
            if ($ok) { set_transient('cfb_settings_notice_ok', implode("\n", $trace), 60); delete_transient('cfb_settings_notice_err'); }
            else     { set_transient('cfb_settings_notice_err', implode("\n", $trace), 60); delete_transient('cfb_settings_notice_ok'); }
        }

        return $san;
    }

    public function settings_save_notices(){
        if (!current_user_can('manage_options')) return;
        if (isset($_GET['page']) && $_GET['page'] === 'cfb-settings') {
            if ($msg = get_transient('cfb_settings_notice_ok')) {
                echo '<div class="notice notice-success"><p><strong>Conexión OK:</strong><br><pre style="white-space:pre-wrap">'.esc_html($msg).'</pre></p></div>';
                delete_transient('cfb_settings_notice_ok');
            }
            if ($msg = get_transient('cfb_settings_notice_err')) {
                echo '<div class="notice notice-error"><p><strong>Error de conexión:</strong><br><pre style="white-space:pre-wrap">'.esc_html($msg).'</pre></p></div>';
                delete_transient('cfb_settings_notice_err');
            }
        }
    }

    private function reschedule_cron_after_interval_change(){
        $s = $this->get_settings();
        $interval = max(5, min(60, intval($s['check_interval'])));
        $timestamp = wp_next_scheduled($this->cron_hook);
        if ($timestamp) wp_unschedule_event($timestamp, $this->cron_hook);
        add_filter('cron_schedules', function($schedules) use ($interval){
            $schedules['cf_fb_custom'] = ['interval'=>$interval*60,'display'=>'CFB cada '.$interval.' minutos'];
            return $schedules;
        });
        wp_schedule_event(time()+60, 'cf_fb_custom', $this->cron_hook);
    }
    public function add_custom_cron_interval($schedules){
        $s = $this->get_settings();
        $interval = max(5, min(60, intval($s['check_interval'])));
        $schedules['cf_fb_custom'] = ['interval'=>$interval*60,'display'=>'CFB cada '.$interval.' minutos'];
        return $schedules;
    }

    /* ================== Render: Configuración ================== */

    public function render_settings_page(){
        if (!current_user_can('manage_options')) return;
        echo '<div class="wrap"><h1>CF Football Bypass — Configuración</h1>';
        echo '<p>Al guardar se verifica automáticamente la conexión y permisos (no altera tu caché de DNS).</p>';
        echo '<form id="cfb-settings-form" method="post" action="options.php">';
        settings_fields('cfb_settings_group');
        do_settings_sections('cfb_settings_page');
        submit_button('Guardar cambios y verificar');
        echo '</form>';

        // Consola propia de Configuración (muestra último log guardado)
        $last = get_option('cfb_settings_last_trace');
        echo '<div class="notice notice-info" style="padding:10px;white-space:pre-wrap;line-height:1.3;margin-top:10px">';
        echo '<strong>Consola:</strong>';
        echo '<div id="cfb-warn-settings" style="color:#b32d2e;font-weight:600;margin:6px 0 0 0;display:none;">⏳ Espera unos segundos para que se complete la operación…</div>';
        echo '<pre id="cfb-console-pre-settings" style="margin:6px 0 0 0;white-space:pre-wrap;">';
        if (is_array($last) && !empty($last['trace'])) {
            foreach ($last['trace'] as $line) echo esc_html($line)."\n";
        }
        echo '</pre></div>';

        // JS espera/console
        ?>
        <script>
        (function(){
            var form = document.getElementById('cfb-settings-form');
            var warn = document.getElementById('cfb-warn-settings');
            var pre  = document.getElementById('cfb-console-pre-settings');
            if (form) {
                form.addEventListener('submit', function(){
                    if (warn) warn.style.display = '';
                    if (pre) {
                        var ts = new Date().toLocaleTimeString();
                        pre.textContent += '['+ts+'] Enviando ajustes… verificando credenciales y permisos en Cloudflare.\n';
                    }
                });
            }
        })();
        </script>
        <?php
        echo '</div>';
    }

    public function render_logs_page(){
        if (!current_user_can('manage_options')) return;
        $s = $this->get_settings();
        $path = $this->get_log_file_path();
        $enabled = !empty($s['logging_enabled']);
        $entries = $enabled ? $this->read_log_entries(250) : [];
        echo '<div class="wrap"><h1>CF Football Bypass — Logs</h1>';
        echo '<p>Archivo: <code>'.esc_html($path).'</code></p>';
        echo '<p>Estado: <strong>'.esc_html($enabled?__('Activo','cfb'):__('Desactivado','cfb')).'</strong>. ';
        printf('%s</p>', esc_html(sprintf(__('Retención: %d días.','cfb'), intval($s['log_retention_days'] ?? 30))));
        if (!$enabled) {
            echo '<div class="notice notice-warning"><p>'.__('El registro está desactivado. Actívalo en la pestaña de Configuración.','cfb').'</p></div>';
        }
        if ($enabled && empty($entries)) {
            if (!file_exists($path)) {
                echo '<p>'.__('Todavía no hay eventos registrados.','cfb').'</p>';
            } else {
                echo '<p>'.__('El archivo de log existe pero no contiene eventos recientes.','cfb').'</p>';
            }
        }
        if ($enabled && !empty($entries)) {
            echo '<table class="widefat striped" style="margin-top:15px">';
            echo '<thead><tr><th>'.__('Fecha','cfb').'</th><th>'.__('Tipo','cfb').'</th><th>'.__('Mensaje','cfb').'</th><th>'.__('Contexto','cfb').'</th></tr></thead><tbody>';
            foreach ($entries as $entry){
                $time = esc_html($entry['time'] ?? '');
                $type = esc_html($entry['type'] ?? 'info');
                $message = esc_html($entry['message'] ?? '');
                $context = '';
                if (!empty($entry['context']) && is_array($entry['context'])) {
                    $context = esc_html(wp_json_encode($entry['context'], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
                }
                echo '<tr>';
                echo '<td>'.$time.'</td><td>'.$type.'</td><td>'.$message.'</td><td>'.$context.'</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
            echo '<p style="margin-top:10px;font-size:12px;color:#666">'.__('Se muestran los 250 eventos más recientes.','cfb').'</p>';
        }
        echo '</div>';
    }

    public function auth_type_render(){
        $s = $this->get_settings(); ?>
        <select name="<?php echo esc_attr($this->option_name); ?>[auth_type]" id="cfb_auth_type">
            <option value="global" <?php selected($s['auth_type'],'global'); ?>>Global API Key</option>
            <option value="token"  <?php selected($s['auth_type'],'token');  ?>>API Token (Bearer)</option>
        </select>
        <p class="description">Global API Key requiere email; API Token no. Permisos mínimos: Zone:Read, DNS:Read, DNS:Edit.</p>
        <script>
        document.addEventListener('DOMContentLoaded',function(){
            var sel=document.getElementById('cfb_auth_type');
            var email=document.getElementById('cfb_email_input');
            var row=email?email.closest('tr'):null;
            function t(){ if(row) row.style.display=(sel.value==='global')?'':'none'; }
            sel.addEventListener('change',t); t();
        });
        </script>
        <?php
    }
    public function email_render(){
        $s=$this->get_settings();
        printf('<input id="cfb_email_input" type="email" name="%1$s[cloudflare_email]" value="%2$s" class="regular-text" autocomplete="off" />',
            esc_attr($this->option_name), esc_attr($s['cloudflare_email']));
    }
    public function api_key_render(){
        $s=$this->get_settings(); ?>
        <input type="password" autocomplete="new-password" name="<?php echo esc_attr($this->option_name); ?>[cloudflare_api_key]" value="<?php echo esc_attr($s['cloudflare_api_key']); ?>" class="regular-text" />
        <p class="description">Nunca se muestra en trazas ni consola.</p>
        <?php
    }
    public function zone_id_render(){
        $s=$this->get_settings(); ?>
        <input type="text" name="<?php echo esc_attr($this->option_name); ?>[cloudflare_zone_id]" value="<?php echo esc_attr($s['cloudflare_zone_id']); ?>" class="regular-text" />
        <?php
    }
    public function check_interval_render(){
        $s=$this->get_settings();
        printf('<input type="number" min="5" max="60" name="%1$s[check_interval]" value="%2$d" class="small-text" />',
            esc_attr($this->option_name), intval($s['check_interval']));
    }
    public function selected_records_hint(){
        echo '<p class="description">Marca los registros a gestionar en la pestaña <strong>Operación</strong> (usando el caché).</p>';
    }
    public function logging_enabled_render(){
        $s = $this->get_settings();
        $checked = !empty($s['logging_enabled']) ? 'checked' : '';
        echo '<label><input type="checkbox" name="'.esc_attr($this->option_name).'[logging_enabled]" value="1" '.$checked.'> '.__('Guardar acciones en el registro (cron y manuales)','cfb').'</label>';
        echo '<p class="description">'.__('Los registros se guardan en el archivo cfb-actions.log y se muestran en la pestaña Logs.','cfb').'</p>';
    }
    public function log_retention_render(){
        $s = $this->get_settings();
        $days = isset($s['log_retention_days']) ? intval($s['log_retention_days']) : 30;
        printf('<input type="number" min="1" max="365" name="%1$s[log_retention_days]" value="%2$d" class="small-text" />',
            esc_attr($this->option_name), $days);
        echo '<p class="description">'.__('Número de días a conservar registros (mínimo 1).','cfb').'</p>';
    }
    public function cron_secret_render(){
        $s = $this->get_settings();
        $secret = isset($s['cron_secret']) ? $s['cron_secret'] : '';
        echo '<input type="text" name="'.esc_attr($this->option_name).'[cron_secret]" style="width:320px" id="cfb-cron-secret" value="'.esc_attr($secret).'" autocomplete="off" />';
        echo '<p class="description">'.__('Usa este token en el cron externo:','cfb').'</p>';
        $url = add_query_arg(['cfb_cron'=>1,'token'=>$secret], home_url('/wp-cron.php'));
        echo '<code>'.esc_html($url).'</code>';
        echo '<p class="description">'.__('Puedes regenerar el token borrándolo y guardando los ajustes (se creará uno nuevo).','cfb').'</p>';
    }
    public function reset_settings_render(){
        echo '<label><input type="checkbox" name="'.esc_attr($this->option_name).'[reset_settings]" value="1"> '.__('Borrar toda la configuración del plugin al guardar','cfb').'</label>';
        echo '<p class="description" style="color:#b32d2e">'.__('Esta acción elimina credenciales, registros seleccionados, caché DNS y logs. Tendrás que configurar el plugin de nuevo.','cfb').'</p>';
    }

    /* ================== Render: Operación ================== */

    public function render_main_page(){
        if (!current_user_can('manage_options')) return;

        $s = $this->get_settings();
        $sync_trace=[];
        if (!empty($s['cloudflare_zone_id']) && !empty($s['cloudflare_api_key'])){
            $records = $this->fetch_dns_records(['A','AAAA','CNAME'], $sync_trace);
            if (!empty($records)){
                $this->persist_dns_cache($records);
                $this->log_event('manual','Vista Operación: caché DNS sincronizada',[
                    'usuario'=>$this->current_user_label(),
                    'registros'=>count($records)
                ]);
                $s = $this->get_settings();
            } elseif (!empty($sync_trace)) {
                $this->log_event('manual','Vista Operación: no se pudo sincronizar DNS',[
                    'usuario'=>$this->current_user_label(),
                    'detalle'=>$sync_trace
                ]);
            }
        }
        $cache = isset($s['dns_records_cache']) ? $s['dns_records_cache'] : [];
        $sel   = isset($s['selected_records']) ? $s['selected_records'] : [];
        $nonce = wp_create_nonce('cfb_nonce');
        $domain = $this->get_site_domain();
        $check_url = 'https://hayahora.futbol/#comprobador&domain='.rawurlencode($domain);

        echo '<div class="wrap"><h1>CF Football Bypass — Operación</h1>';

        // Intro solicitada
        echo '<p style="max-width:960px;margin-top:6px">';
        echo 'CF Football Bypass es un plugin gratis creado por <a href="'.esc_url('https://colorvivo.com').'" target="_blank" rel="noopener">Color Vivo</a> y ';
        echo '<a href="'.esc_url('https://carrero.es').'" target="_blank" rel="noopener">David Carrero</a> con Twitter X ';
        echo '<a href="'.esc_url('https://x.com/carrero').'" target="_blank" rel="noopener">@carrero</a> para ayudar a que si tu WordPress utiliza WordPress y se ve afectado por los bloqueos indiscriminados de la liga ';
        echo 'puedas desactivar el CDN temporalmente. Sabemos que no es la mejor solución pero al menos no perdemos visitas.';
        echo '</p>';

        // Layout a 2 columnas
        echo '<div class="cfb-flex" style="display:flex;gap:20px;align-items:flex-start;">';

        // Columna izquierda (principal)
        echo '<div class="cfb-main" style="flex:1;min-width:0;">';

        echo '<p>Zona: <code>'.esc_html($this->mask($s['cloudflare_zone_id'])).'</code> · Auth: <strong>'.($s['auth_type']==='token'?'Token':'Global Key').'</strong> · ';
        echo 'Dominio: <strong>'.esc_html($domain).'</strong> — <a href="'.esc_url($check_url).'" target="_blank" rel="noopener">Abrir comprobador</a></p>';

        echo '<h2 class="title">Registros DNS en caché</h2>';
        echo '<div id="cfb-dns-list">';
        if (empty($cache)) {
            echo '<p>No hay registros en caché. Pulsa “Probar conexión y cargar DNS”.</p>';
        } else {
            $this->echo_dns_table($cache, $sel);
        }
        echo '</div>';

        echo '<p style="margin-top:10px">';
        echo '<button class="button button-primary" id="cfb-test" data-nonce="'.esc_attr($nonce).'">Probar conexión y cargar DNS</button> ';
        echo '<button class="button" id="cfb-check">Comprobación manual ahora</button> ';
        echo '<button class="button" id="cfb-off">Forzar Proxy OFF (DNS Only)</button> ';
        echo '<button class="button" id="cfb-on">Forzar Proxy ON (CDN)</button> ';
        echo '<button class="button" id="cfb-diag">Diagnóstico WP-Cron</button>';
        echo '</p>';

        echo '<div id="cfb-console" class="notice notice-info" style="padding:10px;white-space:pre-wrap;line-height:1.3">';
        echo '<strong>Consola:</strong>';
        echo '<div id="cfb-warn" style="color:#b32d2e;font-weight:600;margin:6px 0 0 0;display:none;">⏳ Espera unos segundos para que se complete la operación…</div>';
        echo '<pre id="cfb-console-pre" style="margin:6px 0 0 0;white-space:pre-wrap;"></pre>';
        echo '</div>';

        $calc = $this->compute_statuses_from_json(true);
        $general_si_no = ($calc['general']==='SÍ')?'SI':'NO';
        $domain_si_no  = ($calc['domain']==='SÍ') ?'SI':'NO';
        $ips_str       = !empty($calc['domain_ips']) ? implode(', ', array_map('esc_html', $calc['domain_ips'])) : '—';
        $last_update   = $calc['last_update'] ?: '—';

        echo '<div class="cfb-summary" style="margin-top:10px">';
        echo '<p><strong>Hay bloqueos en algunas IPs ahora:</strong> <span id="cfb-summary-general">'.esc_html($general_si_no).'</span></p>';
        echo '<p><strong>¿Está este dominio '.esc_html($domain).' bloqueado?</strong> <span id="cfb-summary-domain">'.esc_html($domain_si_no).'</span> (IPs: <span id="cfb-summary-ips">'.$ips_str.'</span> <a href="#" id="cfb-refresh-ips" class="button-link">Actualizar IPs</a>)</p>';
        echo '<p><strong>Última actualización (JSON de IPs):</strong> <span id="cfb-summary-lastupdate">'.esc_html($last_update).'</span></p>';
        echo '</div>';

        echo '</div>'; // .cfb-main

        // Columna derecha (sidebar)
        echo '<aside class="cfb-aside" style="width:320px;max-width:100%;">';

        echo '<div class="postbox" style="padding:12px;">';
        echo '<h3 style="margin:0 0 10px 0;">#LaLigaGate</h3>';
        echo '<ul style="margin:0;padding-left:18px;">';
        echo '<li><a href="'.esc_url('https://hayahora.futbol/').'" target="_blank" rel="noopener">Hay ahora fútbol</a></li>';
        echo '<li><a href="'.esc_url('https://laligagate.com/').'" target="_blank" rel="noopener">Web La Liga Gate</a></li>';
        echo '<li><a href="'.esc_url('https://x.com/laligagate').'" target="_blank" rel="noopener">Sigue en X @LaLigaGate</a></li>';
        echo '</ul>';
        echo '</div>';

        echo '<div class="postbox" style="padding:12px;">';
        echo '<h3 style="margin:0 0 10px 0;">Servidores VPN</h3>';
        echo '<ul style="margin:0;padding-left:18px;">';
        echo '<li><a href="'.esc_url('https://revistacloud.com/protonvpn').'" target="_blank" rel="noopener">VPN Proton (aff)</a></li>';
        echo '<li><a href="'.esc_url('https://revistacloud.com/nvpn').'" target="_blank" rel="noopener">NordVPN (aff)</a></li>';
        echo '</ul>';
        echo '</div>';

        echo '<div class="postbox" style="padding:12px;">';
        echo '<h3 style="margin:0 0 10px 0;">Noticias y actualidad</h3>';
        echo '<ul style="margin:0;padding-left:18px;">';
        echo '<li><a href="'.esc_url('https://revistacloud.com').'" target="_blank" rel="noopener">Actualidad Revista Cloud</a></li>';
        echo '<li><a href="'.esc_url('https://redes-sociales.com').'" target="_blank" rel="noopener">Noticias Redes Sociales</a></li>';
        echo '<li><a href="'.esc_url('https://wpdirecto.com').'" target="_blank" rel="noopener">WordPress Directo</a></li>';
        echo '</ul>';
        echo '</div>';

        echo '<div class="postbox" style="padding:12px;">';
        echo '<h3 style="margin:0 0 10px 0;">Enlaces Seguridad</h3>';
        echo '<ul style="margin:0;padding-left:18px;">';
        echo '<li><a href="'.esc_url('https://revistacloud.com/backblaze').'" target="_blank" rel="noopener">Backup para tu Ordenador (aff)</a></li>';
        echo '<li><a href="'.esc_url('https://revistacloud.com/1passwordes').'" target="_blank" rel="noopener">Gestor de contraseñas (aff)</a></li>';
        echo '<li><a href="'.esc_url('https://opensecurity.es').'" target="_blank" rel="noopener">Noticias OpenSecurity</a></li>';
        echo '</ul>';
        echo '<div style="text-align:center;margin-top:12px;padding-top:10px;border-top:1px solid #e2e2e2;">';
        echo '<p style="font-size:11px;color:#666;margin:0;">Desarrollado por <a href="'.esc_url('https://carrero.es').'" target="_blank" rel="noopener">David Carrero</a></p>';
        echo '</div>';
        echo '</div>';

        echo '</aside>';

        echo '</div>'; // .cfb-flex

        $this->print_main_js();
        echo '</div>';
    }

    private function echo_dns_table($records, $selected){
        echo '<table class="widefat striped"><thead><tr>';
        echo '<th style="width:28px;"></th><th>Nombre</th><th>Tipo</th><th>Contenido</th><th>Proxied</th><th>TTL</th>';
        echo '</tr></thead><tbody>';
        foreach ($records as $r) {
            $id=$r['id']??''; $name=$r['name']??''; $type=$r['type']??''; $cont=$r['content']??'';
            $px=array_key_exists('proxied',$r)?$r['proxied']:null; $ttl=$r['ttl']??'';
            $checked = in_array($id,(array)$selected,true)?' checked':'';
            echo '<tr>';
            echo '<td><input type="checkbox" name="'.esc_attr($this->option_name).'[selected_records][]" value="'.esc_attr($id).'"'.$checked.'></td>';
            echo '<td>'.esc_html($name).'</td>';
            echo '<td>'.esc_html($type).'</td>';
            echo '<td>'.esc_html($cont).'</td>';
            echo '<td>'.($px===null?'—':($px?'ON':'OFF')).'</td>';
            echo '<td>'.esc_html($ttl).'</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

    private function print_main_js(){ ?>
        <script>
        (function(){
            var ajaxURL = (typeof window.ajaxurl === 'string' && window.ajaxurl) ? window.ajaxurl : '<?php echo esc_js(admin_url('admin-ajax.php','relative')); ?>';
            var consolePre = document.getElementById('cfb-console-pre');
            var warn = document.getElementById('cfb-warn');
            function println(msg){ if (!consolePre) return; var ts=new Date().toLocaleTimeString(); consolePre.textContent += '['+ts+'] '+msg+'\n'; }
            function clearConsole(){ if (consolePre) consolePre.textContent=''; }
            function showWait(show){ if (warn) warn.style.display = show ? '' : 'none'; }
            function selection(){
                var ids=[], wrap=document.getElementById('cfb-dns-list');
                if(!wrap) return ids;
                wrap.querySelectorAll('input[type="checkbox"][name="<?php echo esc_js($this->option_name); ?>[selected_records][]"]:checked').forEach(function(cb){ ids.push(cb.value); });
                return ids;
            }
            function post(action, extra, cb){
                var data=new FormData();
                data.append('action', action);
                var testBtn=document.getElementById('cfb-test');
                data.append('_ajax_nonce', testBtn ? testBtn.dataset.nonce : '');
                var sel = selection();
                sel.forEach(function(id){ data.append('selected[]', id); });
                // (informativo) mandamos la selección en bruto por si se usa en el servidor
                data.append('<?php echo esc_js($this->option_name); ?>[selected_records]', JSON.stringify(sel));

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
                .finally(function(){ showWait(false); });
            }
            function refreshTable(html){
                var wrap=document.getElementById('cfb-dns-list'); if(wrap && html) wrap.innerHTML=html;
            }
            function refreshSummary(callback){
                post('cfb_get_status', null, function(res){
                    if(res && res.success && res.data){
                        var d=res.data;
                        var g=document.getElementById('cfb-summary-general');
                        var dd=document.getElementById('cfb-summary-domain');
                        var i=document.getElementById('cfb-summary-ips');
                        var l=document.getElementById('cfb-summary-lastupdate');
                        if(g) g.textContent = (d.general==='SÍ')?'SI':'NO';
                        if(dd) dd.textContent = (d.domain==='SÍ')?'SI':'NO';
                        if(i) i.textContent = (d.ips && d.ips.length) ? d.ips.join(', ') : '—';
                        if(l) l.textContent = d.last_update || '—';
                    }
                    if (typeof callback === 'function') callback(res);
                });
            }

            document.getElementById('cfb-test').addEventListener('click', function(e){
                e.preventDefault(); clearConsole(); showWait(true);
                println('Probar conexión y cargar DNS: iniciando…');
                post('cfb_test_connection', null, function(res){
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
            document.getElementById('cfb-check').addEventListener('click', function(e){
                e.preventDefault(); clearConsole(); showWait(true);
                println('Comprobación manual: ejecutando…');
                post('cfb_manual_check', null, function(res){
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
            document.getElementById('cfb-off').addEventListener('click', function(e){
                e.preventDefault(); clearConsole(); showWait(true);
                println('Forzar Proxy OFF (DNS Only): iniciando…');
                post('cfb_force_deactivate', null, function(res){
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
            document.getElementById('cfb-on').addEventListener('click', function(e){
                e.preventDefault(); clearConsole(); showWait(true);
                println('Forzar Proxy ON (CDN): iniciando…');
                post('cfb_force_activate', null, function(res){
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
            document.getElementById('cfb-diag').addEventListener('click', function(e){
                e.preventDefault(); clearConsole(); showWait(true);
                println('Diagnóstico WP-Cron…');
                post('cfb_cron_diagnostics', null, function(res){
                    if (res.success && res.data && res.data.msg) println(res.data.msg);
                    else if (res.data && res.data.raw) println(String(res.data.raw).substring(0,1000));
                });
            });
            var refreshIpsBtn=document.getElementById('cfb-refresh-ips');
            if (refreshIpsBtn){
                refreshIpsBtn.addEventListener('click', function(e){
                    e.preventDefault(); clearConsole(); showWait(true);
                    println('Actualizando IPs del dominio…');
                    refreshSummary(function(res){
                        if (res && res.success) println('IPs actualizadas.');
                    });
                });
            }
        })();
        </script>
    <?php }

    /* ================== Verificación rápida (para settings) ================== */

    private function api_headers($settings){
        $h = ['Content-Type'=>'application/json'];
        if ($settings['auth_type']==='global') {
            $h['X-Auth-Email'] = $settings['cloudflare_email'];
            $h['X-Auth-Key']   = $settings['cloudflare_api_key'];
        } else {
            $h['Authorization'] = 'Bearer '.$settings['cloudflare_api_key'];
        }
        return $h;
    }

    private function quick_settings_test($settings, &$trace){
        if (empty($settings['cloudflare_api_key'])) { $this->trace($trace, 'Falta API Key/Token.'); return false; }
        if (empty($settings['cloudflare_zone_id'])) { $this->trace($trace, 'Falta Zone ID.'); return false; }
        if ($settings['auth_type']==='global' && empty($settings['cloudflare_email'])) { $this->trace($trace, 'Falta email para Global API Key.'); return false; }

        $headers = $this->api_headers($settings);

        if ($settings['auth_type']==='token') {
            $url = 'https://api.cloudflare.com/client/v4/user/tokens/verify';
            $this->trace($trace, 'GET '.$url);
            $r = wp_remote_get($url, ['headers'=>$headers,'timeout'=>20]);
            if (is_wp_error($r)) { $this->trace($trace, 'WP_Error verify: '.$r->get_error_message()); return false; }
            $code = wp_remote_retrieve_response_code($r);
            $body = wp_remote_retrieve_body($r);
            $json = json_decode($body, true);
            $cfRay = wp_remote_retrieve_header($r,'cf-ray');
            $this->trace($trace, 'verify HTTP '.$code.' success='.((!empty($json['success']))?'true':'false').' cf-ray='.($cfRay?:'—'));
            if ($code!==200 || empty($json['success'])) {
                $err = isset($json['errors'][0]['message']) ? $json['errors'][0]['message'] : 'verify failed';
                $this->trace($trace, 'Error: '.$err);
                return false;
            }
        } else {
            $url = 'https://api.cloudflare.com/client/v4/user';
            $this->trace($trace, 'GET '.$url);
            $r = wp_remote_get($url, ['headers'=>$headers,'timeout'=>20]);
            if (is_wp_error($r)) { $this->trace($trace, 'WP_Error user: '.$r->get_error_message()); return false; }
            $code = wp_remote_retrieve_response_code($r);
            $body = wp_remote_retrieve_body($r);
            $json = json_decode($body, true);
            $cfRay = wp_remote_retrieve_header($r,'cf-ray');
            $this->trace($trace, 'user HTTP '.$code.' success='.((!empty($json['success']))?'true':'false').' cf-ray='.($cfRay?:'—'));
            if ($code!==200 || empty($json['success'])) { $this->trace($trace, 'Error autenticando Global Key.'); return false; }
        }

        $url = 'https://api.cloudflare.com/client/v4/zones/'.rawurlencode($settings['cloudflare_zone_id']);
        $this->trace($trace, 'GET '.$url);
        $r = wp_remote_get($url, ['headers'=>$headers,'timeout'=>20]);
        if (is_wp_error($r)) { $this->trace($trace, 'WP_Error zone: '.$r->get_error_message()); return false; }
        $code = wp_remote_retrieve_response_code($r);
        $body = wp_remote_retrieve_body($r);
        $json = json_decode($body, true);
        $cfRay = wp_remote_retrieve_header($r,'cf-ray');
        $zone_name = is_array($json) && !empty($json['result']['name']) ? $json['result']['name'] : '?';
        $this->trace($trace, 'zone HTTP '.$code.' success='.((!empty($json['success']))?'true':'false').' name='.$zone_name.' cf-ray='.($cfRay?:'—'));
        if ($code!==200 || empty($json['success'])) { $this->trace($trace,'Error accediendo a la zona (ID o permisos).'); return false; }

        $site_domain = $this->get_site_domain();
        if (!$this->domain_matches_zone($site_domain, $zone_name)){
            $this->trace($trace, 'Zone mismatch: dominio='.$site_domain.' zona='.$zone_name);
            return false;
        }

        $url = 'https://api.cloudflare.com/client/v4/zones/'.rawurlencode($settings['cloudflare_zone_id']).'/dns_records?per_page=50&page=1';
        $this->trace($trace, 'GET '.$url);
        $r = wp_remote_get($url, ['headers'=>$headers,'timeout'=>30]);
        if (is_wp_error($r)) { $this->trace($trace, 'WP_Error dns: '.$r->get_error_message()); return false; }
        $code = wp_remote_retrieve_response_code($r);
        $body = wp_remote_retrieve_body($r);
        $json = json_decode($body, true);
        $cfRay = wp_remote_retrieve_header($r,'cf-ray');
        $this->trace($trace, 'dns HTTP '.$code.' success='.((!empty($json['success']))?'true':'false').' count='.(isset($json['result'])?count($json['result']):0).' cf-ray='.($cfRay?:'—'));
        if ($code!==200 || empty($json['success'])) {
            $err = isset($json['errors'][0]['message']) ? $json['errors'][0]['message'] : 'dns list failed';
            $this->trace($trace, 'Error DNS: '.$err);
            return false;
        }
        $this->trace($trace, 'Conexion OK y lectura de DNS disponible.');
        return true;
    }

    /* ================== Cloudflare: lectura/edición ================== */

    private function fetch_dns_records(array $allowed_types=['A','AAAA','CNAME'], &$trace=null){
        $s=$this->get_settings();
        if (empty($s['cloudflare_api_key']) || empty($s['cloudflare_zone_id'])) { $this->trace($trace,'CF API DNS: falta API key o Zone ID.'); return []; }
        if ($s['auth_type']==='global' && empty($s['cloudflare_email'])) { $this->trace($trace,'CF API DNS: falta email para Global API Key.'); return []; }
        $headers=$this->api_headers($s);

        $page=1; $per_page=100; $accum=[]; $max_pages=50; $total_pages=1;
        do {
            $url='https://api.cloudflare.com/client/v4/zones/'.rawurlencode($s['cloudflare_zone_id']).'/dns_records?per_page='.$per_page.'&page='.$page;
            $this->trace($trace,'GET '.$url);
            $r=wp_remote_get($url,['headers'=>$headers,'timeout'=>30]);
            if (is_wp_error($r)){ $this->trace($trace,'CF API DNS WP_Error: '.$r->get_error_message()); break; }
            $code=wp_remote_retrieve_response_code($r);
            $body=wp_remote_retrieve_body($r);
            $cfRay=wp_remote_retrieve_header($r,'cf-ray');
            if ($code!==200){ $this->trace($trace,'CF API DNS HTTP '.$code.' cf-ray='.($cfRay?:'—').' body: '.substr((string)$body,0,300)); break; }
            if (!$body){ $this->trace($trace,'CF API DNS: cuerpo vacio.'); break; }
            $json=json_decode($body,true);
            if (!is_array($json)){ $this->trace($trace,'CF API DNS: JSON invalido: '.substr((string)$body,0,300)); break; }
            if (empty($json['success'])){ $this->trace($trace,'CF API DNS: success=false err='.substr(wp_json_encode($json['errors']),0,300)); break; }
            if (!isset($json['result'])){ $this->trace($trace,'CF API DNS: sin result.'); break; }

            $ri=$json['result_info']??null;
            if ($ri && isset($ri['total_count'],$ri['per_page']) && intval($ri['per_page'])>0){
                $total_pages=(int)ceil($ri['total_count']/$ri['per_page']);
                $this->trace($trace,'result_info: count='.(isset($ri['count'])?$ri['count']:'?').' total='.$ri['total_count'].' per_page='.$ri['per_page'].' page='.$ri['page'].' total_pages='.$total_pages);
            } else {
                $this->trace($trace,'result_info no disponible; se asume 1 pagina.');
                $total_pages=$page;
            }

            foreach ($json['result'] as $rr){
                $t=isset($rr['type'])?strtoupper($rr['type']):'';
                if (!in_array($t,$allowed_types,true)) continue;
                $accum[]=[
                    'id'=>(string)($rr['id']??''),
                    'name'=>(string)($rr['name']??''),
                    'type'=>$t,
                    'content'=>(string)($rr['content']??''),
                    'proxied'=>array_key_exists('proxied',$rr)?(bool)$rr['proxied']:null,
                    'ttl'=>intval($rr['ttl']??1),
                ];
            }
            $this->trace($trace,'Pagina '.$page.' leida. Acumulados='.count($accum));
            $page++;
        } while ($page <= $total_pages && $page <= $max_pages);

        return $accum;
    }

    private function update_record_proxy_status($record_id, $proxied_on, $detailed=false){
        $s=$this->get_settings();
        if (empty($s['cloudflare_api_key']) || empty($s['cloudflare_zone_id'])) return $detailed?['success'=>false,'error'=>'Falta API key o Zone ID']:false;
        if ($s['auth_type']==='global' && empty($s['cloudflare_email'])) return $detailed?['success'=>false,'error'=>'Falta email para Global API Key']:false;

        if (empty($s['dns_records_cache'])) { $this->persist_dns_cache($this->fetch_dns_records()); $s=$this->get_settings(); }
        $existing=null;
        foreach ((array)$s['dns_records_cache'] as $r){ if (!empty($r['id']) && $r['id']===$record_id){ $existing=$r; break; } }
        if (!$existing){
            $this->persist_dns_cache($this->fetch_dns_records()); $s=$this->get_settings();
            foreach ((array)$s['dns_records_cache'] as $r){ if (!empty($r['id']) && $r['id']===$record_id){ $existing=$r; break; } }
            if (!$existing) return $detailed?['success'=>false,'error'=>'Registro no encontrado en caché tras refresco']:false;
        }

        $type=strtoupper($existing['type']??''); if (!in_array($type,['A','AAAA','CNAME'],true)) return $detailed?['success'=>false,'error'=>"Tipo $type no admite Proxy",'record'=>$existing]:false;
        if (array_key_exists('proxied',$existing) && (bool)$existing['proxied']===(bool)$proxied_on) return $detailed?['success'=>true,'skipped'=>true,'record'=>$existing]:true;

        $headers=$this->api_headers($s);
        $url='https://api.cloudflare.com/client/v4/zones/'.rawurlencode($s['cloudflare_zone_id']).'/dns_records/'.rawurlencode($record_id);
        $ttl=intval($existing['ttl']??1); if ($proxied_on) $ttl=1; // ON => ttl=auto
        $payload=['type'=>$type?:'A','name'=>$existing['name']??'','content'=>$existing['content']??'','ttl'=>$ttl,'proxied'=>(bool)$proxied_on];

        $r=wp_remote_request($url,['method'=>'PUT','headers'=>$headers,'timeout'=>30,'body'=>wp_json_encode($payload)]);
        if (is_wp_error($r)) return $detailed?['success'=>false,'error'=>$r->get_error_message(),'record'=>$existing]:false;

        $code=wp_remote_retrieve_response_code($r); $body=wp_remote_retrieve_body($r); $json=json_decode($body,true);
        if ($code!==200 || !is_array($json) || empty($json['success'])){
            $err='Error Cloudflare'; if (is_array($json)&&!empty($json['errors'][0]['message'])) $err.=': '.$json['errors'][0]['message']; elseif($code!==200) $err.=' (HTTP '.$code.')';
            return $detailed?['success'=>false,'error'=>$err,'record'=>$existing,'response'=>$json]:false;
        }

        foreach ($s['dns_records_cache'] as &$rr){ if (!empty($rr['id']) && $rr['id']===$record_id){ $rr['proxied']=(bool)$proxied_on; break; } }
        $this->persist_dns_cache($s['dns_records_cache']);
        return $detailed?['success'=>true,'record'=>$existing]:true;
    }

    /* ================== Capa de caché ================== */

    private function persist_dns_cache(array $records){
        $s=$this->get_settings();
        $s['dns_records_cache']=$records;
        $s['dns_cache_last_sync']=current_time('mysql');
        $ok = $this->save_settings($s); // pasa por sanitize_settings y se respeta el caché entrante
        $this->log('Persistencia cache DNS: '.($ok?'OK':'SIN CAMBIOS').' ('.count($records).' registros).');
    }

    /* ================== Lógica automática por JSON ================== */

    public function check_football_and_manage_cloudflare(){
        $settings=$this->get_settings();
        $calc=$this->compute_statuses_from_json();
        $general=$calc['general'];
        $domain=$calc['domain'];
        $now=current_time('mysql');
        $should_disable = ($domain==='SÍ');
        $desiredProxied = !$should_disable; // dominio bloqueado => OFF, si no => ON

        $updated=0;
        $detailed_results=[];
        if (!empty($settings['selected_records'])){
            $this->persist_dns_cache($this->fetch_dns_records());
            foreach ($settings['selected_records'] as $rid){
                $res = $this->update_record_proxy_status($rid,$desiredProxied,true);
                if (is_array($res) && !empty($res['success'])){
                    if (empty($res['skipped'])) $updated++;
                    $detailed_results[$rid] = $res;
                }
            }
        }
        $settings['last_check']=$now;
        $settings['last_status_general']=($general==='SÍ')?'SI':'NO';
        $settings['last_status_domain']=($domain==='SÍ')?'SI':'NO';
        $settings['last_update']=$calc['last_update'] ?? $settings['last_update'];
        $this->save_settings($settings);
        $this->log("Auto-check: general={$settings['last_status_general']} domain={$settings['last_status_domain']} updated=$updated");
        $changes = [];
        if (!empty($settings['selected_records'])){
            foreach ($settings['selected_records'] as $rid){
                $changes[] = $this->summarize_record_change($rid, $desiredProxied, $detailed_results[$rid] ?? null);
            }
        }

        $log_context = [
            'general'=>$settings['last_status_general'],
            'domain'=>$settings['last_status_domain'],
            'registros_seleccionados'=>count($settings['selected_records'] ?? []),
        ];
        $log_context['accion'] = $should_disable ? 'Proxy OFF (dominio bloqueado)' : 'Proxy ON (dominio sin bloqueo)';
        if ($updated>0) {
            $log_context['cambios']='Se aplicaron '.$updated.' cambios de proxy.';
        } else {
            $log_context['cambios']='Sin cambios; estado deseado ya aplicado.';
        }
        if (!empty($changes)) $log_context['detalle']=$changes;

        $this->log_event('cron', 'Auto-check ejecutado', $log_context);
    }

    private function summarize_record_change($record_id, $desiredProxied, $result=null){
        $s=$this->get_settings();
        $info=['id'=>$record_id];
        $recordData = null;
        if (is_array($result) && isset($result['record'])) {
            $recordData = $result['record'];
            $info['accion'] = empty($result['skipped']) ? 'actualizado' : 'sin cambio';
            if (!empty($result['error'])) $info['accion'] = 'error';
        }
        if (!$recordData){
            foreach ((array)$s['dns_records_cache'] as $r){
                if (!empty($r['id']) && $r['id']===$record_id){
                    $recordData = $r;
                    break;
                }
            }
        }
        if ($recordData){
            $info['name']=$recordData['name'] ?? '';
            $info['tipo']=$recordData['type'] ?? '';
            $info['nuevo_estado']=$desiredProxied ? 'ON' : 'OFF';
            $current = isset($recordData['proxied']) ? ($recordData['proxied'] ? 'ON' : 'OFF') : 'desconocido';
            $info['estado_resultante']=$current;
            if (!isset($info['accion'])){
                $info['accion'] = ($current === $info['nuevo_estado']) ? 'sin cambio' : 'actualizado';
            }
        } else {
            $info['accion']='registro no encontrado';
        }
        return $info;
    }

    /* ================== JSON bloqueos ================== */

    function compute_statuses_from_json($force_refresh_ips=false){
        $domain=$this->get_site_domain();
        $data=$this->fetch_status_json();
        if ($data===null){ return ['general'=>'NO','domain'=>'NO','fresh'=>false,'domain_ips'=>[],'last_update'=>'']; }

        $map=$data['ip_map']??[];
        $last_update_str=$data['last_update']??'';
        $general_blocked=false;
        foreach ($map as $ip=>$blocked){ if ($blocked===true){ $general_blocked=true; break; } }

        $resolved_ips=$this->resolve_domain_ips($domain, $force_refresh_ips);
        $domain_blocked=false;
        foreach ($resolved_ips as $ip){ if (isset($map[$ip]) && $map[$ip]===true){ $domain_blocked=true; break; } }

        return [
            'general'     => $general_blocked?'SÍ':'NO',
            'domain'      => $domain_blocked  ?'SÍ':'NO',
            'fresh'       => $data['fresh']??false,
            'domain_ips'  => $resolved_ips,
            'last_update' => $last_update_str,
        ];
    }
    private function get_site_domain(){
        $home=home_url('/'); $host=wp_parse_url($home, PHP_URL_HOST); return $host ?: ($_SERVER['HTTP_HOST'] ?? '');
    }
    private function resolve_domain_ips($domain, $force=false){
        $cache_key = 'cfb_domain_ips_cache';
        $cached = get_transient($cache_key);
        if (!$force && is_array($cached) && isset($cached['domain']) && $cached['domain']===$domain && isset($cached['ips'])){
            return (array)$cached['ips'];
        }

        $ips=[];
        if ($domain){
            $records=dns_get_record($domain, DNS_A + DNS_AAAA);
            if (is_array($records)){ foreach ($records as $r){ if (!empty($r['type']) && ($r['type']==='A'||$r['type']==='AAAA')){ $ip=$r['type']==='A' ? ($r['ip']??'') : ($r['ipv6']??''); if ($ip) $ips[]=$ip; } } }
        }
        $ips = array_values(array_unique($ips));
        set_transient($cache_key, ['domain'=>$domain,'ips'=>$ips], MINUTE_IN_SECONDS);
        return $ips;
    }
    private function locate_local_data_json(){
        $candidates=[
            WP_CONTENT_DIR.'/cfb-data/data.json',
            WP_CONTENT_DIR.'/uploads/cfb/data.json',
            plugin_dir_path(__FILE__).'data.json',
            plugin_dir_path(__FILE__).'estado/data.json',
        ];
        $candidates=apply_filters('cfb_local_data_json_paths',$candidates);
        foreach ($candidates as $p){
            if (!is_string($p) || $p==='') continue;
            if ($p[0] !== '/' && !preg_match('@^[A-Za-z]:\\\\@',$p)) $p = trailingslashit(ABSPATH).ltrim($p,'/');
            if (file_exists($p) && is_readable($p) && filesize($p)>0) return $p;
        }
        return null;
    }
    private function fetch_status_json(){
        // Always try remote; keep a local copy and use it for processing
        $uploads_dir = WP_CONTENT_DIR . '/uploads/cfb';
        $local_path  = $uploads_dir . '/data.json';

        $local_body = null; $last_local = null;
        if (file_exists($local_path) && is_readable($local_path) && filesize($local_path)>0){
            $local_body = @file_get_contents($local_path);
            $json_local = @json_decode($local_body, true);
            if (is_array($json_local) && !empty($json_local['lastUpdate']) && is_string($json_local['lastUpdate'])) {
                $last_local = $json_local['lastUpdate'];
            }
        }

        $url = apply_filters('cfb_remote_data_json_url','https://hayahora.futbol/estado/data.json');
        $resp = wp_remote_get($url, ['timeout'=>25,'redirection'=>5,'user-agent'=>'CFB/1.0; '.home_url('/')]);
        $remote_ok=false; $remote_body=null; $last_remote=null;
        if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp)===200){
            $remote_body = wp_remote_retrieve_body($resp);
            $tmp = @json_decode($remote_body, true);
            if (is_array($tmp)){
                $remote_ok = true;
                if (!empty($tmp['lastUpdate']) && is_string($tmp['lastUpdate'])) $last_remote = $tmp['lastUpdate'];
            }
        }

        $should_write = false;
        if ($remote_ok){
            if (!$local_body) { $should_write = true; }
            else {
                if ($last_remote && $last_local) {
                    try {
                        $dr = new DateTime($last_remote); $dl = new DateTime($last_local);
                        if ($dr > $dl) $should_write = true;
                    } catch (Exception $e) {
                        if (md5($remote_body) !== md5($local_body)) $should_write = true;
                    }
                } else {
                    if (md5($remote_body) !== md5($local_body)) $should_write = true;
                }
            }
        }

        if ($should_write){
            if (!file_exists($uploads_dir)) { @wp_mkdir_p($uploads_dir); }
            if (is_dir($uploads_dir) && is_writable($uploads_dir)){
                @file_put_contents($local_path, $remote_body);
                $local_body = $remote_body;
                $last_local = $last_remote;
                $this->log('[CFB] Local data.json actualizado.');
            } else {
                $this->log('[CFB] No se puede escribir en '.$uploads_dir);
            }
        }

        // Choose processing body (prefer local if exists)
        $body = $local_body ?: ($remote_ok ? $remote_body : null);
        if (!is_string($body) || $body==='') return null;

        $json = json_decode($body, true);
        if (!is_array($json)) { $this->log('[CFB] JSON decode failed'); return null; }

        $last_update_str = (!empty($json['lastUpdate']) && is_string($json['lastUpdate'])) ? $json['lastUpdate'] : '';
        $fresh=false; $now_ts=current_time('timestamp');
        if ($last_update_str){
            $ts = strtotime($last_update_str);
            if ($ts){
                $diff = $now_ts - $ts;
                if (isset($this->fresh_window)) { $fresh = ($diff>=0 && $diff <= $this->fresh_window); }
            }
        }

        $map=$this->extract_ip_block_map($json);
        $this->log('[CFB] data.json procesado; IPs bloqueadas hoy='.count($map));
        return ['fresh'=>$fresh,'ip_map'=>$map,'last_update'=>$last_update_str];
    }
    private function extract_ip_block_map($json){
        $map=[]; $ips=null;
        foreach (['ips','ip','data','results'] as $k){ if (isset($json[$k])){ $ips=$json[$k]; break; } }
        if ($ips===null){
            $all=true;
            if (is_array($json)){ foreach ($json as $k=>$v){ if (!filter_var($k,FILTER_VALIDATE_IP)){ $all=false; break; } } if ($all) $ips=$json; }
        }
        if (!is_array($ips)) return [];
        if ($this->is_assoc($ips)){
            foreach ($ips as $ip=>$val){
                if (!is_string($ip)) continue;
                if (is_bool($val)||is_int($val)||is_string($val)){ $b=$this->normalize_bool_like($val); if ($b!==null) $map[$ip]=$b; continue; }
                if (is_array($val)){
                    $latest=null;
                    $statechanges = $this->array_value_ci($val, 'statechanges');
                    if (is_array($statechanges)){
                        $maxTs=null; $st=null;
                        foreach ($statechanges as $chg){
                            $ts=null; if (isset($chg['timestamp'])) $ts=strtotime((string)$chg['timestamp']); elseif(isset($chg['time'])) $ts=strtotime((string)$chg['time']);
                            if ($ts===false) $ts=null;
                            $s = isset($chg['state']) ? $this->normalize_bool_like($chg['state']) : (isset($chg['status']) ? $this->normalize_bool_like($chg['status']) : null);
                            if ($s!==null && ($maxTs===null || ($ts!==null && $ts>$maxTs))){ $maxTs=$ts; $st=$s; }
                        }
                        if ($st!==null) $latest=$st;
                    }
                    foreach (['isps','providers','carriers'] as $k){
                        if ($latest!==null) break;
                        $sub = $this->array_value_ci($val, $k);
                        if (is_array($sub)){
                            $any=null;
                            foreach ($sub as $ispVal){
                                if (!is_array($ispVal)) continue;
                                $statechangesSub = $this->array_value_ci($ispVal, 'statechanges');
                                if (is_array($statechangesSub)){
                                    $maxTs=null; $st=null;
                                    foreach ($statechangesSub as $chg){
                                        $ts=null; if (isset($chg['timestamp'])) $ts=strtotime((string)$chg['timestamp']); elseif(isset($chg['time'])) $ts=strtotime((string)$chg['time']);
                                        if ($ts===false) $ts=null;
                                        $s=isset($chg['state']) ? $this->normalize_bool_like($chg['state']) : (isset($chg['status']) ? $this->normalize_bool_like($chg['status']) : null);
                                        if ($s!==null && ($maxTs===null || ($ts!==null && $ts>$maxTs))){ $maxTs=$ts; $st=$s; }
                                    }
                                    if ($st!==null) $any = $any===null ? $st : ($any || $st);
                                } else {
                                    foreach (['blocked','isBlocked','status'] as $kk){
                                        $v = $this->array_value_ci($ispVal, $kk);
                                        if ($v !== null){ $b=$this->normalize_bool_like($v); if ($b!==null) $any = $any===null ? $b : ($any || $b); }
                                    }
                                }
                            }
                            if ($any!==null) $latest=$any;
                        }
                    }
                    if ($latest!==null) $map[$ip]=(bool)$latest;
                    foreach (['blocked','isBlocked','status'] as $kk){
                        $v = $this->array_value_ci($val, $kk);
                        if ($v !== null){ $b=$this->normalize_bool_like($v); if ($b!==null) { $map[$ip]=$b; continue 2; } }
                    }
                }
            }
        } else {
            foreach ($ips as $entry){
                if (!is_array($entry)) continue;
                $ip=(string)($entry['ip']??''); if (!$ip) continue;
                $b=null;
                foreach (['blocked','isBlocked','status'] as $k){
                    $v = $this->array_value_ci($entry, $k);
                    if ($v !== null){ $b=$this->normalize_bool_like($v); if ($b!==null) break; }
                }
                if ($b===null){
                    $statechanges = $this->array_value_ci($entry, 'statechanges');
                    if (is_array($statechanges)){
                        $maxTs=null; $st=null;
                        foreach ($statechanges as $chg){
                            $ts=null; if (isset($chg['timestamp'])) $ts=strtotime((string)$chg['timestamp']); elseif(isset($chg['time'])) $ts=strtotime((string)$chg['time']);
                            if ($ts===false) $ts=null;
                            $s=isset($chg['state']) ? $this->normalize_bool_like($chg['state']) : (isset($chg['status']) ? $this->normalize_bool_like($chg['status']) : null);
                            if ($s!==null && ($maxTs===null || ($ts!==null && $ts>$maxTs))){ $maxTs=$ts; $st=$s; }
                        }
                        if ($st!==null) $b=$st;
                    }
                }
                if ($b!==null) $map[$ip]=(bool)$b;
            }
        }
        return $map;
    }

    /* ================== AJAX ================== */

    private function persist_selected_from_ajax(){
        $s=$this->get_settings();
        $sel = isset($_POST['selected']) ? array_map('sanitize_text_field',(array)$_POST['selected']) : [];
        if ($sel !== ($s['selected_records'] ?? [])) {
            $s['selected_records'] = $sel;
            $this->save_settings($s);
            $this->log('Seleccion de registros persistida: '.count($sel).' ids.');
        }
        return $sel;
    }

    public function ajax_test_connection(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfb_nonce');

        $s=$this->get_settings();
        $log=[];
        $this->trace($log, 'Auth: '.($s['auth_type']==='token'?'Token':'Global').' | Email: '.($s['auth_type']==='global'?$s['cloudflare_email']:'—'));
        $this->trace($log, 'Zone ID: '.$this->mask($s['cloudflare_zone_id']));

        $headers=$this->api_headers($s);

        if ($s['auth_type']==='token'){
            $url='https://api.cloudflare.com/client/v4/user/tokens/verify';
            $this->trace($log,'GET '.$url);
            $r=wp_remote_get($url,['headers'=>$headers,'timeout'=>20]);
            if (is_wp_error($r)) wp_send_json_error(['message'=>'Error verificando token: '.$r->get_error_message(),'log'=>$log]);
            $code=wp_remote_retrieve_response_code($r); $body=wp_remote_retrieve_body($r); $json=json_decode($body,true);
            $cfRay=wp_remote_retrieve_header($r,'cf-ray');
            $this->trace($log,'HTTP '.$code.' verify='.(is_array($json)&&!empty($json['success'])?'true':'false').' cf-ray='.($cfRay?:'—'));
            if ($code!==200 || empty($json['success'])) wp_send_json_error(['message'=>'Token inválido o sin permisos (verify).','log'=>$log,'http'=>$code,'raw'=>substr((string)$body,0,800)]);
        } else {
            $url='https://api.cloudflare.com/client/v4/user';
            $this->trace($log,'GET '.$url);
            $r=wp_remote_get($url,['headers'=>$headers,'timeout'=>20]);
            if (is_wp_error($r)) wp_send_json_error(['message'=>'Error verificando usuario: '.$r->get_error_message(),'log'=>$log]);
            $code=wp_remote_retrieve_response_code($r); $body=wp_remote_retrieve_body($r); $json=json_decode($body,true);
            $cfRay=wp_remote_retrieve_header($r,'cf-ray');
            $this->trace($log,'HTTP '.$code.' user='.(is_array($json)&&!empty($json['success'])?'true':'false').' cf-ray='.($cfRay?:'—'));
            if ($code!==200 || empty($json['success'])) wp_send_json_error(['message'=>'Autenticación fallida con Global API Key/Email.','log'=>$log,'http'=>$code,'raw'=>substr((string)$body,0,800)]);
        }

        if (!empty($s['cloudflare_zone_id'])){
            $url='https://api.cloudflare.com/client/v4/zones/'.rawurlencode($s['cloudflare_zone_id']);
            $this->trace($log,'GET '.$url);
            $r=wp_remote_get($url,['headers'=>$headers,'timeout'=>20]);
            if (is_wp_error($r)) wp_send_json_error(['message'=>'Error comprobando zona: '.$r->get_error_message(),'log'=>$log]);
            $code=wp_remote_retrieve_response_code($r); $body=wp_remote_retrieve_body($r); $json=json_decode($body,true);
            $cfRay=wp_remote_retrieve_header($r,'cf-ray');
            $zone_name=is_array($json)&&!empty($json['result']['name'])?$json['result']['name']:'?';
            $this->trace($log,'HTTP '.$code.' zone='.(is_array($json)&&!empty($json['success'])?'true':'false').' name='.$zone_name.' cf-ray='.($cfRay?:'—'));
            if ($code!==200 || empty($json['success'])) wp_send_json_error(['message'=>'No se pudo acceder a la zona (ID incorrecto o sin permisos).','log'=>$log,'http'=>$code,'raw'=>substr((string)$body,0,800)]);
            $site_domain = $this->get_site_domain();
            if (!$this->domain_matches_zone($site_domain, $zone_name)){
                wp_send_json_error(['message'=>'El Zone ID no corresponde con el dominio actual ('.$site_domain.').','log'=>$log]);
            }
        } else {
            wp_send_json_error(['message'=>'Zone ID vacío.','log'=>$log]);
        }

        // Lee DNS y PERSISTE caché
        $this->trace($log,'Obteniendo registros DNS (A, AAAA, CNAME)…');
        $records=$this->fetch_dns_records(['A','AAAA','CNAME'],$log);
        $count=count($records);
        $this->trace($log,'Total registros validos: '.$count);

        $sample=array_slice($records,0,10);
        foreach ($sample as $rr){
            $this->trace($log, sprintf(' - %s %s (%s) proxied=%s ttl=%s id=%s',
                $rr['type'],$rr['name'],$rr['content'], ($rr['proxied']===null?'—':($rr['proxied']?'ON':'OFF')), $rr['ttl'], $this->mask($rr['id'])
            ));
        }
        if ($count>10) $this->trace($log,' ... +'.($count-10).' mas');

        if (empty($records)) wp_send_json_error(['message'=>'No se obtuvieron registros (permiso DNS:Read?).','log'=>$log]);

        $this->persist_dns_cache($records);
        $this->trace($log,'Cache actualizado y guardado.');

        // Persistir selección marcada (si la hay)
        $sel = $this->persist_selected_from_ajax();

        // Render tabla con lo recien guardado
        $s2=$this->get_settings();
        ob_start();
        $this->echo_dns_table($s2['dns_records_cache'], $sel ?: ($s2['selected_records'] ?? []));
        $html=ob_get_clean();

        $this->log_event('manual', 'Test de conexión ejecutado', [
            'usuario'=>$this->current_user_label(),
            'registros_en_cache'=>count($s2['dns_records_cache'] ?? []),
            'seleccionados'=>count($s2['selected_records'] ?? [])
        ]);

        wp_send_json_success(['html'=>$html,'log'=>$log]);
    }

    public function ajax_get_status(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfb_nonce');
        $calc=$this->compute_statuses_from_json();
        wp_send_json_success(['general'=>$calc['general'],'domain'=>$calc['domain'],'ips'=>$calc['domain_ips'],'last_update'=>$calc['last_update']]);
    }

    public function ajax_manual_check(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfb_nonce');
        $log=[]; $this->trace($log,'Ejecucion manual: comprobando JSON de IPs y aplicando politica…');
        $this->persist_selected_from_ajax();
        $this->check_football_and_manage_cloudflare(); $s=$this->get_settings();
        $this->log_event('manual', 'Comprobación manual ejecutada', [
            'usuario'=>$this->current_user_label(),
            'general'=>$s['last_status_general'] ?? 'NO',
            'dominio'=>$s['last_status_domain'] ?? 'NO'
        ]);
        wp_send_json_success(['last'=>$s['last_check'],'general'=>$s['last_status_general'],'domain'=>$s['last_status_domain'],'last_update'=>$s['last_update'] ?? '','log'=>$log]);
    }

    public function ajax_force_deactivate(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfb_nonce');
        $log=[]; $this->trace($log,'Forzar OFF: refrescando estado real desde Cloudflare…');

        $sel = $this->persist_selected_from_ajax();
        if (empty($sel)) wp_send_json_error(['message'=>'No hay registros seleccionados.','log'=>$log]);

        $before=$this->fetch_dns_records(['A','AAAA','CNAME'],$log); if (!empty($before)) $this->persist_dns_cache($before);
        $ok=0; $fail=0; $lines=[];
        foreach ($sel as $rid){
            $res=$this->update_record_proxy_status($rid,false,true);
            if (is_array($res) && !empty($res['success'])){
                if (!empty($res['skipped'])) $lines[]='SKIP: '.($res['record']['name'] ?? $rid).' (ya OFF)';
                else { $ok++; $lines[]='OK: '.($res['record']['name'] ?? $rid).' -> OFF'; }
            } else {
                $fail++; $lines[]='ERR: '.(($res['record']['name'] ?? $rid)).' '.(is_array($res)&&!empty($res['error'])?$res['error']:'');
            }
        }
        $after=$this->fetch_dns_records(['A','AAAA','CNAME'],$log); if (!empty($after)) $this->persist_dns_cache($after);

        $s2=$this->get_settings(); ob_start(); $this->echo_dns_table($s2['dns_records_cache'], $sel); $html=ob_get_clean();
        $msg="Proxy OFF en $ok registros".($fail?"; fallidos: $fail":"").".";
        $this->log_event('manual', 'Forzar Proxy OFF', [
            'usuario'=>$this->current_user_label(),
            'procesados'=>count($sel),
            'ok'=>$ok,
            'errores'=>$fail
        ]);
        wp_send_json_success(['message'=>$msg,'report'=>implode("\n",$lines),'html'=>$html,'log'=>array_merge($log,$lines,[$msg])]);
    }

    public function ajax_force_activate(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfb_nonce');
        $log=[]; $this->trace($log,'Forzar ON: refrescando estado real desde Cloudflare…');

        $sel = $this->persist_selected_from_ajax();
        if (empty($sel)) wp_send_json_error(['message'=>'No hay registros seleccionados.','log'=>$log]);

        $before=$this->fetch_dns_records(['A','AAAA','CNAME'],$log); if (!empty($before)) $this->persist_dns_cache($before);
        $ok=0; $fail=0; $lines=[];
        foreach ($sel as $rid){
            $res=$this->update_record_proxy_status($rid,true,true);
            if (is_array($res) && !empty($res['success'])){
                if (!empty($res['skipped'])) $lines[]='SKIP: '.($res['record']['name'] ?? $rid).' (ya ON)';
                else { $ok++; $lines[]='OK: '.($res['record']['name'] ?? $rid).' -> ON'; }
            } else {
                $fail++; $lines[]='ERR: '.(($res['record']['name'] ?? $rid)).' '.(is_array($res)&&!empty($res['error'])?$res['error']:'');
            }
        }
        $after=$this->fetch_dns_records(['A','AAAA','CNAME'],$log); if (!empty($after)) $this->persist_dns_cache($after);

        $s2=$this->get_settings(); ob_start(); $this->echo_dns_table($s2['dns_records_cache'], $sel); $html=ob_get_clean();
        $msg="Proxy ON en $ok registros".($fail?"; fallidos: $fail":"").".";
        $this->log_event('manual', 'Forzar Proxy ON', [
            'usuario'=>$this->current_user_label(),
            'procesados'=>count($sel),
            'ok'=>$ok,
            'errores'=>$fail
        ]);
        wp_send_json_success(['message'=>$msg,'report'=>implode("\n",$lines),'html'=>$html,'log'=>array_merge($log,$lines,[$msg])]);
    }

    public function ajax_cron_diagnostics(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfb_nonce');
        $s=$this->get_settings(); $mins=max(5,min(60,intval($s['check_interval'])));
        $nextTs=wp_next_scheduled($this->cron_hook);
        $next=$nextTs?date_i18n('Y-m-d H:i:s',$nextTs):'—';
        $nowTs=current_time('timestamp');
        $cronState='OK';
        if ($nextTs && $nextTs <= $nowTs - MINUTE_IN_SECONDS) {
            $cronState='ATRASADO (WP-Cron no ha podido ejecutarse)';
        }
        $msg="Cron hook: {$this->cron_hook}\nIntervalo: {$mins} min\nSiguiente ejecucion: {$next}\nEstado cron: {$cronState}\nUltima comprobacion: ".($s['last_check']?:'—')."\nGeneral (bloqueos IPs): ".($s['last_status_general']?:'—')."\nDominio bloqueado: ".($s['last_status_domain']?:'—')."\nUltima actualizacion (JSON de IPs): ".(($s['last_update']??'')?:'—')."\nRegistros sincronizados: ".(($s['dns_cache_last_sync']??'')?:'—');
        wp_send_json_success(['msg'=>$msg]);
    }
}

new CloudflareFootballBypass();
