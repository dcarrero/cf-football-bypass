=== CF Football Bypass ===
Contributors: davidcarrero
Tags: cloudflare, dns, football, bypass, ip-blocking
Requires at least: 5.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.8.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: cf-football-bypass
Domain Path: /languages

Automatically manages Cloudflare configuration during football matches to avoid mass IP blocks affecting legitimate websites in Spain.

== Description ==

CF Football Bypass is a WordPress plugin created by David Carrero Fernandez-Baillo to help Spanish website owners protect their legitimate sites from collateral damage caused by mass IP blocks ordered during football matches. The project is open source (GPLv2) and available on GitHub: https://github.com/dcarrero/cf-football-bypass

The plugin automatically monitors football events in Spain by querying hayahora.futbol and, based on the result, manages Cloudflare DNS records to toggle between Proxied and DNS Only modes. This prevents legitimate visitors from being affected by judicial blocks targeting pirate football streaming.

= The Problem =

In Spain, during football matches, mass IP blocks are enforced by judicial orders to combat pirate streaming. These blocks also affect legitimate websites that have nothing to do with football, causing traffic and revenue losses.

= The Solution =

When football is detected:
- Automatically disables the Cloudflare proxy for selected DNS records
- Your website switches to DNS Only mode, avoiding potentially blocked Cloudflare IPs
- After the configured cooldown period, automatically re-enables the Cloudflare proxy

= Key Features =

Full Automation
- Automatic monitoring every X minutes (configurable 5-60 min)
- Automatic bypass activation/deactivation
- Integrated WordPress cron system

Dual Cloudflare Authentication Support
- Global API Key (traditional)
- API Token with specific permissions (more secure)

Granular Control
- Specific DNS record selection (A, AAAA, and CNAME)
- Configurable bypass duration (60-600 minutes)
- Customizable cooldown interval after disabling Cloudflare
- Manual control for special cases

Informative Dashboard
- Real-time football status
- Last check performed
- Bypass status (active/inactive)

Additional Tools
- Cloudflare connection test button
- Manual football status check
- Manual activation/deactivation buttons
- Detailed logging for debugging and auditing
- Protected endpoint for external cron

== Installation ==

1. Download and Install
   - Download the plugin zip file
   - Extract (or upload the resulting folder) to `wp-content/plugins/cf-football-bypass/`
   - Go to your WordPress dashboard > Plugins > CF Football Bypass > Activate

2. Cloudflare Configuration
   - Go to Settings > CF Football Bypass
   - Select your authentication type (Global API Key or API Token)
   - Enter your Cloudflare credentials
   - Add your domain's Zone ID

3. Plugin Configuration
   - Set the check interval (recommended: 15 minutes)
   - Adjust the cooldown interval after disabling Cloudflare (default: 60 minutes)
   - Click "Test connection and load DNS"
   - Select the DNS records you want to manage
   - Save the configuration

= Getting Cloudflare Credentials =

For Global API Key:
1. Go to Cloudflare > My Profile > API Tokens
2. In "API Keys", copy your "Global API Key"
3. You will also need your account email

For API Token (recommended):
1. Go to Cloudflare > My Profile > API Tokens
2. Click "Create Token"
3. Use the "Custom" template
4. Required permissions:
   - Zone:Read (to read zone information)
   - DNS:Read (to list DNS records)
   - DNS:Edit (to modify proxy status)

== External Services ==

This plugin connects to the following external services:

= hayahora.futbol =
The plugin periodically queries the endpoint https://hayahora.futbol/estado/data.json to obtain information about active IP blocks during football events in Spain. This service is free and open source.
- URL: https://hayahora.futbol/
- Privacy Policy: The service does not collect personal data from plugin users.

= Cloudflare API =
The plugin uses the official Cloudflare API (https://api.cloudflare.com/client/v4/) to manage your zone's DNS records. It requires API credentials that you provide.
- URL: https://api.cloudflare.com/
- Terms of Service: https://www.cloudflare.com/terms/
- Privacy Policy: https://www.cloudflare.com/privacypolicy/

= Affiliate Links =
The plugin's operation page includes affiliate links clearly marked with "(aff)" to VPN services and security tools. These links are optional and do not affect the plugin's functionality.

== Frequently Asked Questions ==

= Is it safe to use this plugin? =
Yes. The plugin only modifies the proxy status of Cloudflare (Proxied/DNS Only) for the records you select. It does not delete or modify the content of DNS records.

= What happens if football detection fails? =
In case of an error querying hayahora.futbol, the plugin assumes there is NO football for safety, maintaining the current state without making changes.

= Can I use this with any DNS provider? =
No, this plugin is specifically designed to work with Cloudflare. Your DNS must be managed by Cloudflare.

= Does it affect my website's SEO? =
It should not negatively affect SEO. The plugin only temporarily changes whether your site goes through the Cloudflare proxy or not. Content and URLs remain the same.

= What happens if I deactivate the plugin during an active bypass? =
When deactivating the plugin, a function automatically runs that re-enables the Cloudflare proxy for all selected records.

= Can I manually control the bypass? =
Yes, the plugin includes buttons to:
- Manually check football status
- Force bypass activation/deactivation
- Test Cloudflare connection

= What DNS record types are supported? =
Currently supports A, AAAA, and CNAME records, which are the most common and affected by IP blocks.

= How does the cron system work? =
See the "Cron and Automation" section for details on wp_cron, external endpoint, and configuration recommendations.

== Cron and Automation ==

= How does the cron system work? =
The plugin uses WordPress internal cron (wp_cron) which runs when there are visits to the website. This is usually sufficient for most sites.

= What if my site has low traffic and cron doesn't run regularly? =
Go to Settings > CF Football Bypass and copy the token from the "External cron" section. With that token you can set up a real server cron:

*/15 * * * * curl -s "https://yourdomain.com/wp-cron.php?cfbcolorvivo_cron=1&token=YOUR_TOKEN_HERE" > /dev/null 2>&1

You can regenerate the token by clearing the field and saving settings (a new one is generated). This endpoint only runs the plugin check, without depending on visits.

= What is the "Cooldown after disabling Cloudflare"? =
This is the waiting time (default 60 minutes) that the plugin respects before checking if Cloudflare can be re-enabled after detecting a block. During this period, the proxy remains in "DNS Only" mode even if the JSON stops marking the domain, avoiding rapid activation/deactivation cycles.

= How do I verify that cron is working correctly? =
In the Operation tab, click "WP-Cron Diagnostics" to see the next execution and the result of the last check. You can also review the integrated logs.

== Logs and Auditing ==

= Where can I see the action history? =
In the CF Football Bypass > Logs menu. It shows the latest automatic executions (internal or external cron) and manual actions with date, detail, and user.

= Can I disable logging? =
Yes. In Settings > CF Football Bypass you can disable logging or adjust retention days (minimum 1). Logs are stored in `wp-content/uploads/cfbcolorvivo-logs/cfbcolorvivo-actions.log` protected with .htaccess.

= How do I verify that cron is working correctly? =
You can check if it's scheduled in Tools > Site Health > Info > Scheduled Events, looking for the 'cfbcolorvivo_check_football_status' event. You can also review WordPress error logs where the plugin records all its actions.

== Changelog ==

= 1.8.5 =
* NEW: Support for Cloudflare Account-owned API Tokens (in addition to User API Tokens and Global API Key)
* NEW: Account ID field shown when Account Token is selected
* UX: Auth type selector now offers three options: Global API Key, User Token, Account Token
* UX: Email and Account ID fields show/hide dynamically based on selected auth type

= 1.8.2 =
* NEW: Server outgoing IP detection shown in Settings to help restrict Cloudflare API Token by IP
* UX: IP is cached for 1 hour and detected from multiple sources for reliability

= 1.8.1 =
* SECURITY: External cron token comparison now uses hash_equals() to prevent timing attacks
* PERFORMANCE: Log pruning throttled to once per day instead of on every log event
* UX: Confirmation dialogs before destructive actions (Force OFF, Force ON, Reset)
* UX: Action buttons are disabled during AJAX operations to prevent double-click
* UX: Local environment detection with friendly warning on Operation page
* CODE: Added uninstall.php for complete cleanup on plugin removal (WP_Filesystem)
* CODE: Replaced deprecated current_time('timestamp') with time() (WP 5.3+)

= 1.8.0 =
* IMPROVEMENT: Changed all prefixes from cfb_ to cfbcolorvivo_ to avoid conflicts with other plugins
* IMPROVEMENT: Changed all CSS/JS identifiers from cfb- to cfbcolorvivo- for uniqueness
* CODE: Settings option renamed to cfbcolorvivo_settings
* CODE: Cron hook renamed to cfbcolorvivo_check_football_status
* CODE: Log directory renamed to cfbcolorvivo-logs
* CODE: All AJAX actions, transients, and filters updated with new prefix

= 1.7.1 =
* FIX: Fixed critical bug in configuration checkboxes that prevented unchecking options once activated
* FIX: "Force Proxy OFF during football" option can now be properly disabled
* FIX: "Action logging" option can now be properly disabled
* FIX: Improved code compliance with WordPress.org plugin guidelines

= 1.7.0 =
* IMPROVEMENT: JavaScript now uses wp_enqueue_script() and wp_add_inline_script() per WordPress.org directory guidelines
* IMPROVEMENT: Removed all inline script blocks from PHP code
* IMPROVEMENT: Dynamic data passed via wp_localize_script() for better code separation
* IMPROVEMENT: admin_enqueue_scripts hook properly implemented with page filtering
* CODE: Complete refactoring of admin assets system

= 1.6.0 =
* SECURITY: Log file moved to wp-content/uploads/cfbcolorvivo-logs/ with .htaccess protection
* SECURITY: IP anonymization in logs for GDPR compliance
* SECURITY: Removed error suppression operators (@) with explicit checks
* SECURITY: Added index.php files to prevent directory listing
* IMPROVEMENT: Full internationalization (i18n) support with cf-football-bypass text domain
* IMPROVEMENT: Plugin header updated with all fields required by WordPress.org
* IMPROVEMENT: Automatic log directory creation with protection
* IMPROVEMENT: Better error handling for file writing
* FIX: Version sync between plugin header and readme.txt

= 1.0.1 =
* Added Cloudflare API Token support
* Improved manual control button with confirmation
* Sidebar with recommended links
* Minor bug fixes
* Better error handling and logging

= 1.0.0 =
* Initial version
* Automatic hayahora.futbol monitoring
* Automatic Cloudflare DNS record management
* Global API Key support
* Admin dashboard
* Integrated cron system

== Upgrade Notice ==

= 1.8.5 =
New: Support for Cloudflare Account-owned API Tokens. You can now use tokens from Manage Account > Account API Tokens in addition to user tokens and Global API Key.

= 1.8.2 =
New: Shows server outgoing IP in Settings so you can restrict your Cloudflare API Token to that IP for extra security.

= 1.8.1 =
Security and usability improvements: timing-safe token comparison, confirmation dialogs, anti double-click, local environment detection, and proper cleanup on uninstall.

= 1.8.0 =
Prefix update: All internal prefixes changed from cfb_ to cfbcolorvivo_ to avoid plugin conflicts. Settings will be migrated automatically if you have existing configuration.

= 1.7.1 =
Important fix: Configuration checkboxes now work correctly. Recommended update if you use the "Force Proxy OFF during football" option.

= 1.7.0 =
WordPress.org guidelines compliance: JavaScript now loads correctly using wp_enqueue_script() and wp_add_inline_script() instead of inline script blocks.

= 1.6.0 =
Version prepared for WordPress.org directory. Includes important security improvements: protected logs, anonymized IPs, and translation support.

= 1.0.1 =
This version adds Cloudflare API Token support (more secure than Global API Key) and improves manual bypass control with security confirmations.

== Server Requirements ==

- WordPress 5.0 or higher
- PHP 7.4 or higher
- PHP Extensions: curl, json
- Permissions: Ability to make outbound HTTP requests
- Cron: Functional WordPress cron system

== Support ==

- Author: David Carrero Fernandez-Baillo
- Website: https://carrero.es
- Contact: https://carrero.es/contacto/

If you need help, send a direct message on X or use the contact form. Issues and improvements are also welcome in the repository: https://github.com/dcarrero/cf-football-bypass

This plugin was born from the real need to protect legitimate websites from the mass blocks affecting the Spanish digital industry during sporting events.

== Specific Use Cases ==

High Traffic Sites
- Allows selecting only critical records (www, root domain)
- Keeps other services (mail, ftp, etc.) always proxied
- Minimizes impact on CDN and cache

Sites with Multiple Subdomains
- Granular control per subdomain
- Different strategies for different services
- Total configuration flexibility

Emergencies and Manual Override
- Manual control buttons for special situations
- Does not depend solely on automatic detection
- Allows quick reaction to failures

== License ==

GPLv2 or later. You are free to use, modify, and distribute this plugin under the terms of the GPL.
