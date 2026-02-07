<?php
/**
 * Plugin Name: CF Football Bypass
 * Plugin URI: https://github.com/dcarrero/cf-football-bypass
 * Description: Opera con Cloudflare para alternar Proxy (ON/CDN) y DNS Only (OFF) según bloqueos, con caché persistente de registros y acciones AJAX. UI separada: Operación y Configuración.
 * Version: 1.8.0
 * Author: David Carrero Fernandez-Baillo
 * Author URI: https://carrero.es
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: cf-football-bypass
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) exit;

final class Cfbcolorvivo_Cloudflare_Football_Bypass
{
    private $option_name    = 'cfbcolorvivo_settings';
    private $cron_hook      = 'cfbcolorvivo_check_football_status';
    private $fresh_window   = 240 * 60; // 4h (informativo)
    private $log_file_path;
    private $log_dir_path;
    private $suspend_reschedule = false;

    public function __construct()
    {
        $this->log_dir_path  = WP_CONTENT_DIR . '/uploads/cfbcolorvivo-logs';
        $this->log_file_path = $this->log_dir_path . '/cfbcolorvivo-actions.log';

        // Traducciones se cargan automáticamente desde WordPress 4.6 para plugins en wordpress.org
        add_action('updated_option', [$this, 'handle_option_updated'], 10, 3);

        add_action('admin_menu', [$this, 'register_menus']);
        add_action('admin_init', [$this, 'settings_init']);
        add_action('admin_notices', [$this, 'settings_save_notices']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);

        add_action($this->cron_hook, [$this, 'check_football_and_manage_cloudflare']);
        add_filter('cron_schedules', [$this, 'add_custom_cron_interval']);

        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);

        add_action('wp_ajax_cfbcolorvivo_test_connection',  [$this, 'ajax_test_connection']);
        add_action('wp_ajax_cfbcolorvivo_manual_check',     [$this, 'ajax_manual_check']);
        add_action('wp_ajax_cfbcolorvivo_get_status',       [$this, 'ajax_get_status']);
        add_action('wp_ajax_cfbcolorvivo_force_activate',   [$this, 'ajax_force_activate']);
        add_action('wp_ajax_cfbcolorvivo_force_deactivate', [$this, 'ajax_force_deactivate']);
        add_action('wp_ajax_cfbcolorvivo_cron_diagnostics', [$this, 'ajax_cron_diagnostics']);
        add_action('init', [$this, 'maybe_process_external_cron']);
    }

    /* ================== Utilidades ================== */

    private function to_ascii($s){
        $t = $s;
        if (function_exists('iconv')) {
            $x = iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$s);
            if ($x !== false && $x !== null) $t = $x;
        }
        $map = [
            '¿'=>'?','¡'=>'!','…'=>'...','—'=>'-','–'=>'-','•'=>'*',
            'á'=>'a','Á'=>'A','é'=>'e','É'=>'E','í'=>'i','Í'=>'I','ó'=>'o','Ó'=>'O','ú'=>'u','Ú'=>'U','ñ'=>'n','Ñ'=>'N','ü'=>'u','Ü'=>'U'
        ];
        return strtr($t, $map);
    }
    private function log($msg){
        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            $out = is_scalar($msg) ? (string)$msg : wp_json_encode($msg, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging when WP_DEBUG_LOG is enabled
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
    private function anonymize_ip($ip){
        if (empty($ip) || !is_string($ip)) return '';
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                return $parts[0] . '.' . $parts[1] . '.xxx.xxx';
            }
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            if (count($parts) >= 4) {
                return $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':xxxx:xxxx:xxxx:xxxx:xxxx';
            }
        }
        return 'xxx.xxx.xxx.xxx';
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
    
    // MODIFICACIÓN: Añadido 'force_proxy_off_override' => 0
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
            'bypass_active'       => 0,
            'bypass_blocked_ips'  => [],
            'bypass_check_cooldown' => 60,
            'bypass_last_change'    => 0,
            'force_proxy_off_override' => 0,  // NUEVO: Override para forzar OFF cuando General=SI
        ];
    }
    
    private function clear_logs_file(){
        $path = $this->get_log_file_path();
        if (file_exists($path)) {
            wp_delete_file($path);
        }
    }

    private function ensure_log_directory(){
        $dir = $this->log_dir_path;
        if (!file_exists($dir)) {
            if (!wp_mkdir_p($dir)) {
                return false;
            }
        }
        $htaccess = $dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $htaccess_content = "# Deny access to log files\n<FilesMatch \"\\.(log|txt)$\">\n    Order Allow,Deny\n    Deny from all\n</FilesMatch>\n\n# Block directory listing\nOptions -Indexes\n";
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing security file to plugin's own log directory
            file_put_contents($htaccess, $htaccess_content);
        }
        $index = $dir . '/index.php';
        if (!file_exists($index)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing index file to plugin's own log directory
            file_put_contents($index, '<?php // Silence is golden');
        }
        return is_dir($dir) && wp_is_writable($dir);
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

        if (!$this->ensure_log_directory()) {
            $this->log('No se puede crear/acceder al directorio de logs');
            return;
        }

        $path = $this->get_log_file_path();
        $entry = [
            'time'    => current_time('mysql'),
            'type'    => (string)$type,
            'message' => $message,
        ];
        if (!empty($context)) $entry['context'] = $context;
        $line = wp_json_encode($entry, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        if ($line === false) return;
        $line .= "\n";

        $written = file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
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
        if (wp_is_writable($path)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing to plugin's own log file
            file_put_contents($path, $data, LOCK_EX);
        }
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
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- External cron uses token-based authentication instead of nonce
        if (!isset($_GET['cfbcolorvivo_cron'])) return;
        $s = $this->get_settings();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Token authentication for external cron
        $token = isset($_GET['token']) ? sanitize_text_field(wp_unslash($_GET['token'])) : '';
        if (empty($s['cron_secret']) || $token !== $s['cron_secret']) {
            wp_die(
                esc_html__('Token inválido', 'cf-football-bypass'),
                esc_html__('Acceso denegado', 'cf-football-bypass'),
                array('response' => 403)
            );
        }
        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $this->log_event('external_cron', 'Cron externo disparado', ['ip'=>$this->anonymize_ip($remote_addr)]);
        $this->check_football_and_manage_cloudflare();
        wp_die('CFB cron OK', '', array('response' => 200));
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
    
    // MODIFICACIÓN: Añadida normalización de 'force_proxy_off_override'
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
            $opt['cron_secret'] = $this->generate_cron_secret();
            $changed = true;
        }
        $cooldown = isset($opt['bypass_check_cooldown']) ? intval($opt['bypass_check_cooldown']) : 60;
        if ($cooldown < 5) $cooldown = 5;
        if ($cooldown > 1440) $cooldown = 1440;
        if (!isset($opt['bypass_check_cooldown']) || $cooldown !== intval($opt['bypass_check_cooldown'])) {
            $opt['bypass_check_cooldown'] = $cooldown;
            $changed = true;
        }
        $opt['bypass_active'] = !empty($opt['bypass_active']) ? 1 : 0;
        if (!isset($opt['bypass_blocked_ips']) || !is_array($opt['bypass_blocked_ips'])) {
            $opt['bypass_blocked_ips'] = [];
            $changed = true;
        } else {
            $normalized_ips = [];
            foreach ($opt['bypass_blocked_ips'] as $ip){
                if (is_string($ip) && $ip !== '') $normalized_ips[] = $ip;
            }
            if ($normalized_ips !== $opt['bypass_blocked_ips']) {
                $opt['bypass_blocked_ips'] = $normalized_ips;
                $changed = true;
            }
        }
        $opt['bypass_last_change'] = isset($opt['bypass_last_change']) ? intval($opt['bypass_last_change']) : 0;
        
        // MODIFICACIÓN: Normalizar force_proxy_off_override
        $opt['force_proxy_off_override'] = !empty($opt['force_proxy_off_override']) ? 1 : 0;
        
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
            $next = wp_next_scheduled($this->cron_hook);
            while ($next) { wp_unschedule_event($next, $this->cron_hook); $next = wp_next_scheduled($this->cron_hook); }
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
            'cfbcolorvivo-main',
            [$this, 'render_main_page'],
            'dashicons-shield',
            66
        );
        add_submenu_page('cfbcolorvivo-main','Operacion','Operación','manage_options','cfbcolorvivo-main',[$this,'render_main_page']);
        add_submenu_page('cfbcolorvivo-main','Configuracion','Configuración','manage_options','cfbcolorvivo-settings',[$this,'render_settings_page']);
        add_submenu_page('cfbcolorvivo-main','Registros','Logs','manage_options','cfbcolorvivo-logs',[$this,'render_logs_page']);
    }

    /* ================== Admin Scripts ================== */

    public function enqueue_admin_scripts($hook){
        // Solo cargar en las páginas del plugin
        if (strpos($hook, 'cfbcolorvivo-') === false && strpos($hook, 'cf-football-bypass') === false) {
            return;
        }

        // Registrar script handle para asociar inline scripts
        wp_register_script('cfbcolorvivo-admin', false, array(), '1.8.0', true);
        wp_enqueue_script('cfbcolorvivo-admin');

        // Pasar datos al JavaScript
        wp_localize_script('cfbcolorvivo-admin', 'cfbcolorvivoData', array(
            'ajaxUrl'    => admin_url('admin-ajax.php'),
            'optionName' => $this->option_name,
        ));

        // Página de operación principal
        if (strpos($hook, 'cfbcolorvivo-main') !== false) {
            wp_add_inline_script('cfbcolorvivo-admin', $this->get_main_page_js());
        }

        // Página de configuración
        if (strpos($hook, 'cfbcolorvivo-settings') !== false) {
            wp_add_inline_script('cfbcolorvivo-admin', $this->get_settings_page_js());
            wp_add_inline_script('cfbcolorvivo-admin', $this->get_auth_type_js());
        }
    }

    private function get_main_page_js(){
        return "(function(){
            var ajaxURL = cfbcolorvivoData.ajaxUrl;
            var consolePre = document.getElementById('cfbcolorvivo-console-pre');
            var warn = document.getElementById('cfbcolorvivo-warn');
            function println(msg){ if (!consolePre) return; var ts=new Date().toLocaleTimeString(); consolePre.textContent += '['+ts+'] '+msg+'\\n'; }
            function clearConsole(){ if (consolePre) consolePre.textContent=''; }
            function showWait(show){ if (warn) warn.style.display = show ? '' : 'none'; }
            function selection(){
                var ids=[], wrap=document.getElementById('cfbcolorvivo-dns-list');
                if(!wrap) return ids;
                wrap.querySelectorAll('input[type=\"checkbox\"][name=\"" . esc_js($this->option_name) . "[selected_records][]\"][checked], input[type=\"checkbox\"][name=\"" . esc_js($this->option_name) . "[selected_records][]\"]:checked').forEach(function(cb){ ids.push(cb.value); });
                return ids;
            }
            function post(action, extra, cb){
                var data=new FormData();
                data.append('action', action);
                var testBtn=document.getElementById('cfbcolorvivo-test');
                data.append('_ajax_nonce', testBtn ? testBtn.dataset.nonce : '');
                var sel = selection();
                sel.forEach(function(id){ data.append('selected[]', id); });
                data.append('" . esc_js($this->option_name) . "[selected_records]', JSON.stringify(sel));

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
                    e.preventDefault(); clearConsole(); showWait(true);
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
                    e.preventDefault(); clearConsole(); showWait(true);
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

    private function get_settings_page_js(){
        return "(function(){
            var form = document.getElementById('cfbcolorvivo-settings-form');
            var warn = document.getElementById('cfbcolorvivo-warn-settings');
            var pre  = document.getElementById('cfbcolorvivo-console-pre-settings');
            if (form) {
                form.addEventListener('submit', function(){
                    if (warn) warn.style.display = '';
                    if (pre) {
                        var ts = new Date().toLocaleTimeString();
                        pre.textContent += '['+ts+'] Enviando ajustes… verificando credenciales y permisos en Cloudflare.\\n';
                    }
                });
            }
        })();";
    }

    private function get_auth_type_js(){
        return "document.addEventListener('DOMContentLoaded',function(){
            var sel=document.getElementById('cfbcolorvivo_auth_type');
            var email=document.getElementById('cfbcolorvivo_email_input');
            var row=email?email.closest('tr'):null;
            function t(){ if(row) row.style.display=(sel.value==='global')?'':'none'; }
            if(sel){ sel.addEventListener('change',t); t(); }
        });";
    }

    /* ================== Settings API ================== */

    // MODIFICACIÓN: Añadido campo 'force_proxy_off_override'
    public function settings_init(){
        register_setting('cfbcolorvivo_settings_group', $this->option_name, [$this, 'sanitize_settings']);

        add_settings_section('cfbcolorvivo_cloudflare_section', __('Credenciales de Cloudflare','cf-football-bypass'), '__return_false', 'cfbcolorvivo_settings_page');
        add_settings_field('auth_type', __('Tipo de autenticación','cf-football-bypass'), [$this,'auth_type_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section');
        add_settings_field('cloudflare_email', __('Email (sólo Global API Key)','cf-football-bypass'), [$this,'email_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section');
        add_settings_field('cloudflare_api_key', __('API Key Global o Token','cf-football-bypass'), [$this,'api_key_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section');
        add_settings_field('cloudflare_zone_id', __('Zone ID','cf-football-bypass'), [$this,'zone_id_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_cloudflare_section');

        add_settings_section('cfbcolorvivo_plugin_section', __('Ajustes del plugin','cf-football-bypass'), '__return_false', 'cfbcolorvivo_settings_page');
        add_settings_field('check_interval', __('Intervalo de comprobación (minutos)','cf-football-bypass'), [$this,'check_interval_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('bypass_check_cooldown', __('Intervalo tras desactivar Cloudflare (min)','cf-football-bypass'), [$this,'bypass_check_cooldown_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('force_proxy_off_override', __('Forzar Proxy OFF durante fútbol','cf-football-bypass'), [$this,'force_proxy_off_override_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('selected_records', __('Registros DNS a gestionar (se cargan en Operación)','cf-football-bypass'), [$this,'selected_records_hint'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('logging_enabled', __('Registro de acciones','cf-football-bypass'), [$this,'logging_enabled_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('log_retention_days', __('Retención de logs (días)','cf-football-bypass'), [$this,'log_retention_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('cron_secret', __('Token para cron externo','cf-football-bypass'), [$this,'cron_secret_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
        add_settings_field('reset_settings', __('Resetear configuración','cf-football-bypass'), [$this,'reset_settings_render'], 'cfbcolorvivo_settings_page', 'cfbcolorvivo_plugin_section');
    }

    // MODIFICACIÓN: Añadido sanitizado de 'force_proxy_off_override'
    public function sanitize_settings($input){
        $existing = get_option($this->option_name, []);
        $san = [];

        // Detectar si viene del formulario de configuración (necesario para manejar checkboxes correctamente)
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified by WordPress Settings API before this callback
        $is_settings_form = !wp_doing_ajax() && isset($_POST['option_page']) && sanitize_text_field(wp_unslash($_POST['option_page']))==='cfbcolorvivo_settings_group';

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
        // FIX: Mismo tratamiento para checkboxes - si viene del formulario y no está marcado, debe ser 0
        if ($is_settings_form) {
            $san['logging_enabled'] = !empty($input['logging_enabled']) ? 1 : 0;
        } else {
            $san['logging_enabled'] = isset($input['logging_enabled']) ? (int)!empty($input['logging_enabled']) : ($existing['logging_enabled'] ?? 1);
        }
        $san['log_retention_days']  = isset($input['log_retention_days']) ? intval($input['log_retention_days']) : ($existing['log_retention_days'] ?? 30);
        $san['bypass_check_cooldown'] = isset($input['bypass_check_cooldown']) ? intval($input['bypass_check_cooldown']) : ($existing['bypass_check_cooldown'] ?? 60);
        $san['cron_secret']         = isset($input['cron_secret']) ? sanitize_text_field($input['cron_secret']) : ($existing['cron_secret'] ?? '');
        $san['bypass_active']       = isset($input['bypass_active']) ? (int)!empty($input['bypass_active']) : ($existing['bypass_active'] ?? 0);
        $san['bypass_blocked_ips']  = array_key_exists('bypass_blocked_ips',$input) ? (array)$input['bypass_blocked_ips'] : ($existing['bypass_blocked_ips'] ?? []);
        $san['bypass_last_change']  = isset($input['bypass_last_change']) ? intval($input['bypass_last_change']) : ($existing['bypass_last_change'] ?? 0);
        
        // MODIFICACIÓN: Sanitizar force_proxy_off_override
        // FIX: Cuando viene del formulario de configuración, los checkboxes desmarcados no envían nada,
        // así que debemos establecer a 0 si no está presente. Cuando viene de AJAX, mantener el valor existente.
        if ($is_settings_form) {
            $san['force_proxy_off_override'] = !empty($input['force_proxy_off_override']) ? 1 : 0;
        } else {
            $san['force_proxy_off_override'] = isset($input['force_proxy_off_override']) ? (int)!empty($input['force_proxy_off_override']) : ($existing['force_proxy_off_override'] ?? 0);
        }
        
        $reset_requested            = !empty($input['reset_settings']);

        // Normaliza estructuras
        list($san,) = $this->normalize_settings($san);

        if ($reset_requested){
            $san = $this->get_default_settings(true);
            $this->clear_logs_file();
            delete_option('cfbcolorvivo_settings_last_trace');
            delete_transient('cfbcolorvivo_settings_notice_ok');
            delete_transient('cfbcolorvivo_settings_notice_err');
            $this->log('Configuración reseteada manualmente.');
        }

        unset($san['reset_settings']);

        // Reprogramar cron si cambia intervalo
        if (!isset($existing['check_interval']) || intval($existing['check_interval']) !== intval($san['check_interval'])) {
            $this->reschedule_cron_after_interval_change();
        }

        // Test sólo si guardas desde la página de ajustes (no AJAX)
        // (variable $is_settings_form ya calculada al inicio de la función)
        if ($is_settings_form) {
            $trace = [];
            $ok = $this->quick_settings_test($san, $trace);
            // Guardar último log para la consola de Configuración
            update_option('cfbcolorvivo_settings_last_trace', [
                'ok'    => (bool)$ok,
                'trace' => $trace,
                'ts'    => current_time('mysql')
            ]);
            if ($ok) { set_transient('cfbcolorvivo_settings_notice_ok', implode("\n", $trace), 60); delete_transient('cfbcolorvivo_settings_notice_err'); }
            else     { set_transient('cfbcolorvivo_settings_notice_err', implode("\n", $trace), 60); delete_transient('cfbcolorvivo_settings_notice_ok'); }
        }

        return $san;
    }

    public function settings_save_notices(){
        if (!current_user_can('manage_options')) return;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only reading page parameter to display notices, no data processing
        if (isset($_GET['page']) && sanitize_text_field(wp_unslash($_GET['page'])) === 'cfbcolorvivo-settings') {
            if ($msg = get_transient('cfbcolorvivo_settings_notice_ok')) {
                echo '<div class="notice notice-success"><p><strong>Conexión OK:</strong><br><pre style="white-space:pre-wrap">'.esc_html($msg).'</pre></p></div>';
                delete_transient('cfbcolorvivo_settings_notice_ok');
            }
            if ($msg = get_transient('cfbcolorvivo_settings_notice_err')) {
                echo '<div class="notice notice-error"><p><strong>Error de conexión:</strong><br><pre style="white-space:pre-wrap">'.esc_html($msg).'</pre></p></div>';
                delete_transient('cfbcolorvivo_settings_notice_err');
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
        echo '<form id="cfbcolorvivo-settings-form" method="post" action="options.php">';
        settings_fields('cfbcolorvivo_settings_group');
        do_settings_sections('cfbcolorvivo_settings_page');
        submit_button('Guardar cambios y verificar');
        echo '</form>';

        // Consola propia de Configuración (muestra último log guardado)
        $last = get_option('cfbcolorvivo_settings_last_trace');
        echo '<div class="notice notice-info" style="padding:10px;white-space:pre-wrap;line-height:1.3;margin-top:10px">';
        echo '<strong>Consola:</strong>';
        echo '<div id="cfbcolorvivo-warn-settings" style="color:#b32d2e;font-weight:600;margin:6px 0 0 0;display:none;">⏳ Espera unos segundos para que se complete la operación…</div>';
        echo '<pre id="cfbcolorvivo-console-pre-settings" style="margin:6px 0 0 0;white-space:pre-wrap;">';
        if (is_array($last) && !empty($last['trace'])) {
            foreach ($last['trace'] as $line) echo esc_html($line)."\n";
        }
        echo '</pre></div>';
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
        echo '<p>Estado: <strong>'.esc_html($enabled?__('Activo','cf-football-bypass'):__('Desactivado','cf-football-bypass')).'</strong>. ';
        // translators: %d is the number of days for log retention
        printf('%s</p>', esc_html(sprintf(__('Retención: %d días.','cf-football-bypass'), intval($s['log_retention_days'] ?? 30))));
        if (!$enabled) {
            echo '<div class="notice notice-warning"><p>'.esc_html__('El registro está desactivado. Actívalo en la pestaña de Configuración.','cf-football-bypass').'</p></div>';
        }
        if ($enabled && empty($entries)) {
            if (!file_exists($path)) {
                echo '<p>'.esc_html__('Todavía no hay eventos registrados.','cf-football-bypass').'</p>';
            } else {
                echo '<p>'.esc_html__('El archivo de log existe pero no contiene eventos recientes.','cf-football-bypass').'</p>';
            }
        }
        if ($enabled && !empty($entries)) {
            echo '<table class="widefat striped" style="margin-top:15px">';
            echo '<thead><tr><th>'.esc_html__('Fecha','cf-football-bypass').'</th><th>'.esc_html__('Tipo','cf-football-bypass').'</th><th>'.esc_html__('Mensaje','cf-football-bypass').'</th><th>'.esc_html__('Contexto','cf-football-bypass').'</th></tr></thead><tbody>';
            foreach ($entries as $entry){
                echo '<tr>';
                echo '<td>'.esc_html($entry['time'] ?? '').'</td>';
                echo '<td>'.esc_html($entry['type'] ?? 'info').'</td>';
                echo '<td>'.esc_html($entry['message'] ?? '').'</td>';
                echo '<td>';
                if (!empty($entry['context']) && is_array($entry['context'])) {
                    echo esc_html(wp_json_encode($entry['context'], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
                }
                echo '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
            echo '<p style="margin-top:10px;font-size:12px;color:#666">'.esc_html__('Se muestran los 250 eventos más recientes.','cf-football-bypass').'</p>';
        }
        echo '</div>';
    }

    public function auth_type_render(){
        $s = $this->get_settings(); ?>
        <select name="<?php echo esc_attr($this->option_name); ?>[auth_type]" id="cfbcolorvivo_auth_type">
            <option value="global" <?php selected($s['auth_type'],'global'); ?>>Global API Key</option>
            <option value="token"  <?php selected($s['auth_type'],'token');  ?>>API Token (Bearer)</option>
        </select>
        <p class="description">Global API Key requiere email; API Token no. Permisos mínimos: Zone:Read, DNS:Read, DNS:Edit.</p>
        <?php
    }
    public function email_render(){
        $s=$this->get_settings();
        printf('<input id="cfbcolorvivo_email_input" type="email" name="%1$s[cloudflare_email]" value="%2$s" class="regular-text" autocomplete="off" />',
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
    public function bypass_check_cooldown_render(){
        $s = $this->get_settings();
        $val = isset($s['bypass_check_cooldown']) ? intval($s['bypass_check_cooldown']) : 60;
        printf('<input type="number" min="5" max="1440" name="%1$s[bypass_check_cooldown]" value="%2$d" class="small-text" />',
            esc_attr($this->option_name), esc_attr($val));
        echo '<p class="description">'.esc_html__('Minutos que deben pasar tras desactivar Cloudflare antes de volver a comprobar si puede reactivarse (5-1440).','cf-football-bypass').'</p>';
    }
    
    // MODIFICACIÓN: Nuevo render para force_proxy_off_override
    public function force_proxy_off_override_render(){
        $s = $this->get_settings();
        $checked = !empty($s['force_proxy_off_override']) ? 'checked' : '';
        echo '<label><input type="checkbox" name="'.esc_attr($this->option_name).'[force_proxy_off_override]" value="1" '.esc_attr($checked).'> '.esc_html__('Desactivar Proxy cuando hay fútbol (General=SI), sin esperar detección de este dominio','cf-football-bypass').'</label>';
        echo '<p class="description" style="color:#d63638;font-weight:600;">'.esc_html__('IMPORTANTE: Con esta opción activada, el proxy se desactivará automáticamente cuando hayahora.futbol indique que hay bloqueos activos (General=SI), aunque tu dominio específico no haya sido detectado como bloqueado.','cf-football-bypass').'</p>';
        echo '<p class="description">'.esc_html__('Útil para evitar falsos negativos cuando sabes que tu sitio es bloqueado durante eventos de fútbol pero la detección de IP no siempre funciona correctamente.','cf-football-bypass').'</p>';
    }
    
    public function logging_enabled_render(){
        $s = $this->get_settings();
        $checked = !empty($s['logging_enabled']) ? 'checked' : '';
        echo '<label><input type="checkbox" name="'.esc_attr($this->option_name).'[logging_enabled]" value="1" '.esc_attr($checked).'> '.esc_html__('Guardar acciones en el registro (cron y manuales)','cf-football-bypass').'</label>';
        echo '<p class="description">'.esc_html__('Los registros se guardan en wp-content/uploads/cfbcolorvivo-logs/ protegidos y se muestran en la pestaña Logs.','cf-football-bypass').'</p>';
    }
    public function log_retention_render(){
        $s = $this->get_settings();
        $days = isset($s['log_retention_days']) ? intval($s['log_retention_days']) : 30;
        printf('<input type="number" min="1" max="365" name="%1$s[log_retention_days]" value="%2$d" class="small-text" />',
            esc_attr($this->option_name), esc_attr($days));
        echo '<p class="description">'.esc_html__('Número de días a conservar registros (mínimo 1).','cf-football-bypass').'</p>';
    }
    public function cron_secret_render(){
        $s = $this->get_settings();
        $secret = isset($s['cron_secret']) ? $s['cron_secret'] : '';
        echo '<input type="text" name="'.esc_attr($this->option_name).'[cron_secret]" style="width:320px" id="cfbcolorvivo-cron-secret" value="'.esc_attr($secret).'" autocomplete="off" />';
        echo '<p class="description">'.esc_html__('Usa este token en el cron externo:','cf-football-bypass').'</p>';
        $url = add_query_arg(['cfbcolorvivo_cron'=>1,'token'=>$secret], home_url('/wp-cron.php'));
        echo '<code>'.esc_html($url).'</code>';
        echo '<p class="description">'.esc_html__('Puedes regenerar el token borrándolo y guardando los ajustes (se creará uno nuevo).','cf-football-bypass').'</p>';
    }
    public function reset_settings_render(){
        echo '<label><input type="checkbox" name="'.esc_attr($this->option_name).'[reset_settings]" value="1"> '.esc_html__('Borrar toda la configuración del plugin al guardar','cf-football-bypass').'</label>';
        echo '<p class="description" style="color:#b32d2e">'.esc_html__('Esta acción elimina credenciales, registros seleccionados, caché DNS y logs. Tendrás que configurar el plugin de nuevo.','cf-football-bypass').'</p>';
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
        $nonce = wp_create_nonce('cfbcolorvivo_nonce');
        $domain = $this->get_site_domain();
        $check_url = 'https://hayahora.futbol/#comprobador&domain='.rawurlencode($domain);

        echo '<div class="wrap"><h1>CF Football Bypass — Operación</h1>';

        // Intro solicitada
        echo '<p style="max-width:960px;margin-top:6px">';
        echo 'CF Football Bypass es un plugin gratis creado por <a href="'.esc_url('https://colorvivo.com').'" target="_blank" rel="noopener">Color Vivo</a> y ';
        echo '<a href="'.esc_url('https://carrero.es').'" target="_blank" rel="noopener">David Carrero Fernandez-Baillo</a> para ayudar a que si tu WordPress se ve afectado por los bloqueos indiscriminados de la liga ';
        echo 'puedas desactivar el CDN temporalmente. Sabemos que no es la mejor solución pero al menos no perdemos visitas.';
        echo '</p>';

        // Layout a 2 columnas
        echo '<div class="cfbcolorvivo-flex" style="display:flex;gap:20px;align-items:flex-start;">';

        // Columna izquierda (principal)
        echo '<div class="cfbcolorvivo-main" style="flex:1;min-width:0;">';

        echo '<p>Zona: <code>'.esc_html($this->mask($s['cloudflare_zone_id'])).'</code> · Auth: <strong>'.($s['auth_type']==='token'?'Token':'Global Key').'</strong> · ';
        echo 'Dominio: <strong>'.esc_html($domain).'</strong> — <a href="'.esc_url($check_url).'" target="_blank" rel="noopener">Abrir comprobador</a></p>';

        echo '<h2 class="title">Registros DNS en caché</h2>';
        echo '<p class="description">Debes seleccionar los registros que debemos controlar y pulsar "Probar conexión y cargar DNS" para actualizar el listado.</p>';
        echo '<div id="cfbcolorvivo-dns-list">';
        if (empty($cache)) {
            echo '<p>No hay registros en caché. Pulsa "Probar conexión y cargar DNS".</p>';
        } else {
            $this->echo_dns_table($cache, $sel);
        }
        echo '</div>';

        echo '<p style="margin-top:10px">';
        echo '<button class="button button-primary" id="cfbcolorvivo-test" data-nonce="'.esc_attr($nonce).'">Probar conexión y cargar DNS</button> ';
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

        $calc = $this->compute_statuses_from_json(true);
        $general_si_no = ($calc['general']==='SÍ')?'SI':'NO';
        $domain_si_no  = ($calc['domain']==='SÍ') ?'SI':'NO';
        $ips_str       = !empty($calc['domain_ips']) ? esc_html(implode(', ', $calc['domain_ips'])) : '—';
        $last_update   = $calc['last_update'] ?: '—';

        echo '<div class="cfbcolorvivo-summary" style="margin-top:10px">';
        echo '<p><strong>Hay bloqueos en algunas IPs ahora:</strong> <span id="cfbcolorvivo-summary-general">'.esc_html($general_si_no).'</span></p>';
        echo '<p><strong>¿Está este dominio '.esc_html($domain).' bloqueado?</strong> <span id="cfbcolorvivo-summary-domain">'.esc_html($domain_si_no).'</span> (IPs: <span id="cfbcolorvivo-summary-ips">'.esc_html($ips_str).'</span> <a href="#" id="cfbcolorvivo-refresh-ips" class="button-link">Actualizar IPs</a>)</p>';
        echo '<p><strong>Última actualización (JSON de IPs):</strong> <span id="cfbcolorvivo-summary-lastupdate">'.esc_html($last_update).'</span></p>';
        echo '</div>';

        echo '</div>'; // .cfbcolorvivo-main

        // Columna derecha (sidebar)
        echo '<aside class="cfbcolorvivo-aside" style="width:320px;max-width:100%;">';

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
        echo '<p style="font-size:11px;color:#666;margin:0;">Desarrollado por <a href="'.esc_url('https://carrero.es').'" target="_blank" rel="noopener">David Carrero Fernandez-Baillo</a></p>';
        echo '</div>';
        echo '</div>';

        echo '</aside>';

        echo '</div>'; // .cfbcolorvivo-flex
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
            echo '<td><input type="checkbox" name="'.esc_attr($this->option_name).'[selected_records][]" value="'.esc_attr($id).'"'.esc_attr($checked).'></td>';
            echo '<td>'.esc_html($name).'</td>';
            echo '<td>'.esc_html($type).'</td>';
            echo '<td>'.esc_html($cont).'</td>';
            echo '<td>'.($px===null?'—':($px?'ON':'OFF')).'</td>';
            echo '<td>'.esc_html($ttl).'</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

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
        $ttl=intval($existing['ttl']??1); if ($proxied_on) $ttl=1;
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
        $ok = $this->save_settings($s);
        $this->log('Persistencia cache DNS: '.($ok?'OK':'SIN CAMBIOS').' ('.count($records).' registros).');
    }

    /* ================== Lógica automática por JSON ================== */
    
    // MODIFICACIÓN CRÍTICA: Añadida lógica de override para forzar OFF cuando General=SI
    public function check_football_and_manage_cloudflare(){
        $settings=$this->get_settings();
        $calc=$this->compute_statuses_from_json();
        $general=$calc['general'];
        $domain=$calc['domain'];
        $blocked_domain_ips = $calc['blocked_domain_ips'] ?? [];
        $stored_blocked = isset($settings['bypass_blocked_ips']) && is_array($settings['bypass_blocked_ips']) ? $settings['bypass_blocked_ips'] : [];
        $now_mysql=current_time('mysql');
        $now_ts=current_time('timestamp');
        $prev_active=!empty($settings['bypass_active']);
        $last_change = isset($settings['bypass_last_change']) ? intval($settings['bypass_last_change']) : 0;
        $cooldown_minutes = isset($settings['bypass_check_cooldown']) ? intval($settings['bypass_check_cooldown']) : 60;
        if ($cooldown_minutes < 5) $cooldown_minutes = 5;
        if ($cooldown_minutes > 1440) $cooldown_minutes = 1440;
        $cooldown_seconds = $cooldown_minutes * 60;

        $should_disable = ($domain==='SÍ');
        $reason = $should_disable ? 'domain_blocked' : 'domain_clear';
        
        // MODIFICACIÓN: Override - forzar OFF cuando General=SI aunque dominio no esté bloqueado
        if (!$should_disable && !empty($settings['force_proxy_off_override']) && $general==='SÍ') {
            $should_disable = true;
            $reason = 'override_general_football';
        }
        
        $cooldown_waiting = false;
        $cooldown_remaining = 0;
        $still_waiting_ips = [];

        if (!$should_disable && $prev_active) {
            $still_waiting_ips = array_intersect($stored_blocked, $blocked_domain_ips);
            if (!empty($still_waiting_ips)) {
                $should_disable = true;
                $reason = 'waiting_previous_ips';
            } elseif ($last_change && ($now_ts - $last_change) < $cooldown_seconds) {
                $should_disable = true;
                $reason = 'cooldown';
                $cooldown_waiting = true;
                $cooldown_remaining = $cooldown_seconds - ($now_ts - $last_change);
            }
        }

        $desiredProxied = !$should_disable;

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

        $settings['last_check']=$now_mysql;
        $settings['last_status_general']=($general==='SÍ')?'SI':'NO';
        $settings['last_status_domain']=($domain==='SÍ')?'SI':'NO';
        $settings['last_update']=$calc['last_update'] ?? $settings['last_update'];

        if ($should_disable) {
            if (!$prev_active) { $settings['bypass_last_change']=$now_ts; }
            $settings['bypass_active']=1;
            $settings['bypass_blocked_ips']=!empty($blocked_domain_ips) ? $blocked_domain_ips : $stored_blocked;
        } else {
            if ($prev_active) { $settings['bypass_last_change']=$now_ts; }
            $settings['bypass_active']=0;
            $settings['bypass_blocked_ips']=[];
        }

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
            'bypass_activo'=>$settings['bypass_active'],
            'cooldown_minutos'=>$cooldown_minutes,
            'motivo'=>$reason,
            'bypass_ultima_modificacion'=>$settings['bypass_last_change'] ?? 0,
            'override_activado'=>!empty($settings['force_proxy_off_override']) ? 1 : 0,
        ];
        if ($should_disable) {
            if ($reason === 'domain_blocked') {
                $log_context['accion'] = 'Proxy OFF (dominio bloqueado)';
            } elseif ($reason === 'override_general_football') {
                $log_context['accion'] = 'Proxy OFF (OVERRIDE: General=SI, fútbol detectado)';
            } elseif ($reason === 'waiting_previous_ips') {
                $log_context['accion'] = 'Proxy OFF (esperando desbloqueo de IPs anteriores)';
            } elseif ($reason === 'cooldown') {
                $log_context['accion'] = 'Proxy OFF (en periodo de enfriamiento)';
            } else {
                $log_context['accion'] = 'Proxy OFF';
            }
        } else {
            $log_context['accion'] = 'Proxy ON (dominio sin bloqueo)';
        }
        if (!empty($settings['bypass_blocked_ips'])) {
            $log_context['ips_bloqueadas'] = $settings['bypass_blocked_ips'];
        }
        if ($cooldown_waiting && $cooldown_remaining > 0) {
            $log_context['cooldown_restante_seg'] = $cooldown_remaining;
            $log_context['cooldown_restante_min'] = max(1, ceil($cooldown_remaining/60));
        }
        if (!empty($still_waiting_ips)) {
            $log_context['ips_pendientes'] = array_values($still_waiting_ips);
        }
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

    public function compute_statuses_from_json($force_refresh_ips=false){
        $domain=$this->get_site_domain();
        $data=$this->fetch_status_json();
        if ($data===null){ return ['general'=>'NO','domain'=>'NO','fresh'=>false,'domain_ips'=>[],'blocked_domain_ips'=>[],'last_update'=>'']; }

        $map=$data['ip_map']??[];
        $last_update_str=$data['last_update']??'';
        $general_blocked=false;
        foreach ($map as $ip=>$blocked){ if ($blocked===true){ $general_blocked=true; break; } }

        $resolved_ips=$this->resolve_domain_ips($domain, $force_refresh_ips);
        $blocked_domain_ips=[];
        $domain_blocked=false;
        foreach ($resolved_ips as $ip){
            if (isset($map[$ip]) && $map[$ip]===true){
                $domain_blocked=true;
                $blocked_domain_ips[]=$ip;
            }
        }

        return [
            'general'     => $general_blocked?'SÍ':'NO',
            'domain'      => $domain_blocked  ?'SÍ':'NO',
            'fresh'       => $data['fresh']??false,
            'domain_ips'  => $resolved_ips,
            'blocked_domain_ips' => $blocked_domain_ips,
            'last_update' => $last_update_str,
        ];
    }
    private function get_site_domain(){
        $home=home_url('/');
        $host=wp_parse_url($home, PHP_URL_HOST);
        if ($host) {
            return $host;
        }
        // Fallback to HTTP_HOST only if home_url parsing fails
        return isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
    }
    private function resolve_domain_ips($domain, $force=false){
        $cache_key = 'cfbcolorvivo_domain_ips_cache';
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
            WP_CONTENT_DIR.'/cfbcolorvivo-data/data.json',
            WP_CONTENT_DIR.'/uploads/cfbcolorvivo/data.json',
            plugin_dir_path(__FILE__).'data.json',
            plugin_dir_path(__FILE__).'estado/data.json',
        ];
        $candidates=apply_filters('cfbcolorvivo_local_data_json_paths',$candidates);
        foreach ($candidates as $p){
            if (!is_string($p) || $p==='') continue;
            if ($p[0] !== '/' && !preg_match('@^[A-Za-z]:\\\\@',$p)) $p = trailingslashit(ABSPATH).ltrim($p,'/');
            if (file_exists($p) && is_readable($p) && filesize($p)>0) return $p;
        }
        return null;
    }
    private function fetch_status_json(){
        $uploads_dir = WP_CONTENT_DIR . '/uploads/cfbcolorvivo';
        $local_path  = $uploads_dir . '/data.json';

        $local_body = null; $last_local = null;
        if (file_exists($local_path) && is_readable($local_path) && filesize($local_path)>0){
            $local_body = file_get_contents($local_path);
            if ($local_body !== false) {
                $json_local = json_decode($local_body, true);
                if (is_array($json_local) && !empty($json_local['lastUpdate']) && is_string($json_local['lastUpdate'])) {
                    $last_local = $json_local['lastUpdate'];
                }
            }
        }

        $url = apply_filters('cfbcolorvivo_remote_data_json_url','https://hayahora.futbol/estado/data.json');
        $resp = wp_remote_get($url, ['timeout'=>25,'redirection'=>5,'user-agent'=>'CFBCV/1.8.0; '.home_url('/')]);
        $remote_ok=false; $remote_body=null; $last_remote=null;
        if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp)===200){
            $remote_body = wp_remote_retrieve_body($resp);
            $tmp = json_decode($remote_body, true);
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
            if (!file_exists($uploads_dir)) {
                wp_mkdir_p($uploads_dir);
            }
            if (is_dir($uploads_dir) && wp_is_writable($uploads_dir)){
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Writing cached JSON to plugin's data directory
                $written = file_put_contents($local_path, $remote_body);
                if ($written !== false) {
                    $local_body = $remote_body;
                    $last_local = $last_remote;
                    $this->log('[CFB] Local data.json actualizado.');
                }
            } else {
                $this->log('[CFB] No se puede escribir en '.$uploads_dir);
            }
        }

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
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified in the calling AJAX handler
        $sel = isset($_POST['selected']) ? array_map('sanitize_text_field', wp_unslash((array)$_POST['selected'])) : [];
        if ($sel !== ($s['selected_records'] ?? [])) {
            $s['selected_records'] = $sel;
            $this->save_settings($s);
            $this->log('Seleccion de registros persistida: '.count($sel).' ids.');
        }
        return $sel;
    }

    public function ajax_test_connection(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfbcolorvivo_nonce');

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

        $sel = $this->persist_selected_from_ajax();

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
        check_ajax_referer('cfbcolorvivo_nonce');
        $calc=$this->compute_statuses_from_json();
        wp_send_json_success(['general'=>$calc['general'],'domain'=>$calc['domain'],'ips'=>$calc['domain_ips'],'last_update'=>$calc['last_update']]);
    }

    public function ajax_manual_check(){
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Permiso denegado','log'=>[]]);
        check_ajax_referer('cfbcolorvivo_nonce');
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
        check_ajax_referer('cfbcolorvivo_nonce');
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
        check_ajax_referer('cfbcolorvivo_nonce');
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
        check_ajax_referer('cfbcolorvivo_nonce');
        $s=$this->get_settings(); $mins=max(5,min(60,intval($s['check_interval'])));
        $nextTs=wp_next_scheduled($this->cron_hook);
        $next=$nextTs?date_i18n('Y-m-d H:i:s',$nextTs):'—';
        $nowTs=current_time('timestamp');
        $cronState='OK';
        if ($nextTs && $nextTs <= $nowTs - MINUTE_IN_SECONDS) {
            $cronState='ATRASADO (WP-Cron no ha podido ejecutarse)';
        }
        $msg="Cron hook: {$this->cron_hook}\nIntervalo: {$mins} min\nSiguiente ejecucion: {$next}\nEstado cron: {$cronState}\nUltima comprobacion: ".($s['last_check']?:'—')."\nGeneral (bloqueos IPs): ".($s['last_status_general']?:'—')."\nDominio bloqueado: ".($s['last_status_domain']?:'—')."\nOverride activo: ".(!empty($s['force_proxy_off_override'])?'SI':'NO')."\nUltima actualizacion (JSON de IPs): ".(($s['last_update']??'')?:'—')."\nRegistros sincronizados: ".(($s['dns_cache_last_sync']??'')?:'—');
        wp_send_json_success(['msg'=>$msg]);
    }
}

new Cfbcolorvivo_Cloudflare_Football_Bypass();
