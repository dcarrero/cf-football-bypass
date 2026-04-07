=== ES Football Bypass for Cloudflare ===
Contributors: dcarrero
Tags: cloudflare, dns, futbol, bypass, bloqueo-ip
Requires at least: 5.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.9.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: es-football-bypass-for-cloudflare
Domain Path: /languages

Gestiona automáticamente Cloudflare durante los partidos de fútbol para evitar que los bloqueos masivos de IP afecten a sitios web legítimos en España.

== Description ==

ES Football Bypass for Cloudflare es un plugin de WordPress creado por David Carrero Fernandez-Baillo para ayudar a los propietarios de sitios web españoles a proteger sus webs legítimas del daño colateral provocado por los bloqueos masivos de IP ordenados durante los partidos de fútbol. El proyecto es de código abierto (GPLv2) y está disponible en GitHub: https://github.com/dcarrero/cf-football-bypass

El plugin monitoriza automáticamente los eventos de fútbol en España consultando hayahora.futbol y, en función del resultado, gestiona los registros DNS de Cloudflare para alternar entre los modos Proxied (CDN) y DNS Only. Así se evita que los visitantes legítimos se vean afectados por los bloqueos judiciales dirigidos contra el streaming pirata de fútbol.

= El problema =

En España, durante los partidos de fútbol, se aplican bloqueos masivos de IP por orden judicial para combatir el streaming pirata. Estos bloqueos afectan también a sitios web legítimos que no tienen nada que ver con el fútbol, provocando pérdidas de tráfico e ingresos.

= La solución =

Cuando se detecta fútbol:
- Desactiva automáticamente el proxy de Cloudflare en los registros DNS seleccionados
- Tu web pasa a modo DNS Only, evitando las IPs de Cloudflare potencialmente bloqueadas
- Tras el periodo de enfriamiento configurado, vuelve a activar el proxy de Cloudflare automáticamente

= Funcionalidades clave =

Automatización completa
- Monitorización automática cada X minutos (configurable de 5 a 60 min)
- Activación y desactivación automática del bypass
- Sistema de cron de WordPress integrado

Soporte de doble autenticación de Cloudflare
- Global API Key (tradicional)
- API Token con permisos específicos (más seguro)

Control granular
- Selección específica de registros DNS (A, AAAA y CNAME)
- Duración del bypass configurable (60-600 minutos)
- Intervalo de enfriamiento personalizable tras desactivar Cloudflare
- Control manual para casos especiales

Panel de control informativo
- Estado del fútbol en tiempo real
- Última comprobación realizada
- Estado del bypass (activo/inactivo)

Herramientas adicionales
- Botón de prueba de conexión con Cloudflare
- Comprobación manual del estado del fútbol
- Botones de activación/desactivación manual
- Registro detallado para depuración y auditoría
- Endpoint protegido para cron externo

== Installation ==

1. Descarga e instalación
   - Descarga el archivo zip del plugin
   - Extráelo (o sube la carpeta resultante) a `wp-content/plugins/es-football-bypass-for-cloudflare/`
   - Ve al escritorio de WordPress > Plugins > ES Football Bypass for Cloudflare > Activar

2. Configuración de Cloudflare
   - Ve a Ajustes > ES Football Bypass for Cloudflare
   - Selecciona el tipo de autenticación (Global API Key o API Token)
   - Introduce tus credenciales de Cloudflare
   - Añade el Zone ID de tu dominio

3. Configuración del plugin
   - Establece el intervalo de comprobación (recomendado: 15 minutos)
   - Ajusta el intervalo de enfriamiento tras desactivar Cloudflare (por defecto: 60 minutos)
   - Pulsa "Probar conexión y cargar DNS"
   - Selecciona los registros DNS que quieres gestionar
   - Guarda la configuración

= Cómo obtener las credenciales de Cloudflare =

Para Global API Key:
1. Ve a Cloudflare > Mi Perfil > API Tokens
2. En "API Keys", copia tu "Global API Key"
3. También necesitarás el email de tu cuenta

Para API Token (recomendado):
1. Ve a Cloudflare > Mi Perfil > API Tokens
2. Pulsa "Create Token"
3. Usa la plantilla "Custom"
4. Permisos necesarios:
   - Zone:Read (para leer información de la zona)
   - DNS:Read (para listar los registros DNS)
   - DNS:Edit (para modificar el estado del proxy)

== External Services ==

Este plugin se conecta a los siguientes servicios externos:

= hayahora.futbol =
El plugin consulta periódicamente el endpoint https://hayahora.futbol/estado/data.json para comprobar si hay bloqueos de IP activos durante eventos de fútbol en España. Esta consulta se ejecuta automáticamente según el intervalo de cron configurado (por defecto: cada 15 minutos) y también puede dispararse manualmente desde el panel de administración.
- Datos enviados: una petición HTTP GET con la URL home del sitio en la cabecera User-Agent. No se transmite ningún dato personal ni de visitantes.
- URL: https://hayahora.futbol/
- Sobre el servicio y privacidad: https://hayahora.futbol/#sobre-los-bloqueos
- Términos de uso: el servicio es gratuito, de código abierto, y no recopila datos personales de los usuarios del plugin ni de sus visitantes.

= API de Cloudflare =
El plugin utiliza la API oficial de Cloudflare (https://api.cloudflare.com/client/v4/) para leer los registros DNS y alternar el estado del proxy (Proxied/DNS Only) en los registros seleccionados. Requiere las credenciales de API que tú proporcionas en los ajustes del plugin. Las credenciales se almacenan en la base de datos de WordPress y se envían vía cabeceras HTTPS a Cloudflare.
- Datos enviados: credenciales de API (en cabeceras), modificaciones de registros DNS (record ID, tipo, nombre, contenido, estado proxied).
- URL: https://api.cloudflare.com/
- Términos del servicio: https://www.cloudflare.com/terms/
- Política de privacidad: https://www.cloudflare.com/privacypolicy/

= Servicios de detección de IP del servidor =
El plugin detecta la dirección IP de salida de tu servidor (mostrada en la página de Ajustes) consultando tres servicios públicos. Solo se devuelve la IP propia del servidor; no se transmite ningún dato personal ni de visitantes. Los resultados se cachean durante 1 hora.
- https://api.ipify.org/ - Proporcionado por ipify. Política de privacidad: https://www.ipify.org/
- https://checkip.amazonaws.com/ - Proporcionado por Amazon Web Services. Política de privacidad: https://aws.amazon.com/privacy/
- https://icanhazip.com/ - Proporcionado por Cloudflare. Política de privacidad: https://www.cloudflare.com/privacypolicy/

= Enlaces de afiliado =
La página de Operación del plugin incluye enlaces de afiliado claramente marcados con "(aff)" a servicios de VPN y herramientas de seguridad. Estos enlaces son opcionales y no afectan al funcionamiento del plugin.

== Frequently Asked Questions ==

= ¿Es seguro usar este plugin? =
Sí. El plugin solo modifica el estado del proxy de Cloudflare (Proxied/DNS Only) en los registros que selecciones. No borra ni modifica el contenido de los registros DNS.

= ¿Qué pasa si falla la detección del fútbol? =
En caso de error al consultar hayahora.futbol, el plugin asume por seguridad que NO hay fútbol, manteniendo el estado actual sin hacer cambios.

= ¿Puedo usarlo con cualquier proveedor de DNS? =
No, este plugin está diseñado específicamente para funcionar con Cloudflare. Tus DNS deben estar gestionados por Cloudflare.

= ¿Afecta al SEO de mi web? =
No debería afectar negativamente al SEO. El plugin solo cambia temporalmente si tu sitio pasa o no por el proxy de Cloudflare. El contenido y las URLs permanecen iguales.

= ¿Qué pasa si desactivo el plugin durante un bypass activo? =
Al desactivar el plugin se ejecuta automáticamente una función que vuelve a activar el proxy de Cloudflare en todos los registros seleccionados.

= ¿Puedo controlar el bypass manualmente? =
Sí, el plugin incluye botones para:
- Comprobar manualmente el estado del fútbol
- Forzar la activación/desactivación del bypass
- Probar la conexión con Cloudflare

= ¿Qué tipos de registros DNS están soportados? =
Actualmente soporta registros A, AAAA y CNAME, que son los más comunes y los más afectados por los bloqueos de IP.

= ¿Cómo funciona el sistema de cron? =
Consulta la sección "Cron y Automatización" para más detalles sobre wp_cron, el endpoint externo y las recomendaciones de configuración.

== Cron and Automation ==

= ¿Cómo funciona el sistema de cron? =
El plugin utiliza el cron interno de WordPress (wp_cron), que se ejecuta cuando hay visitas en el sitio web. Esto suele ser suficiente para la mayoría de sitios.

= ¿Y si mi sitio tiene poco tráfico y el cron no se ejecuta con regularidad? =
Ve a Ajustes > ES Football Bypass for Cloudflare y copia el token de la sección "Cron externo". Con ese token puedes configurar un cron real de servidor:

*/15 * * * * curl -s "https://tudominio.com/wp-cron.php?cfbcolorvivo_cron=1&token=TU_TOKEN_AQUI" > /dev/null 2>&1

Puedes regenerar el token borrando el campo y guardando los ajustes (se creará uno nuevo). Este endpoint solo ejecuta la comprobación del plugin, sin depender de las visitas.

= ¿Qué es el "Intervalo tras desactivar Cloudflare"? =
Es el tiempo de espera (por defecto 60 minutos) que el plugin respeta antes de comprobar si Cloudflare se puede reactivar tras detectar un bloqueo. Durante este periodo, el proxy se mantiene en modo "DNS Only" aunque el JSON deje de marcar el dominio, evitando ciclos rápidos de activación/desactivación.

= ¿Cómo verifico que el cron funciona correctamente? =
En la pestaña Operación, pulsa "Diagnóstico WP-Cron" para ver la próxima ejecución y el resultado de la última comprobación. También puedes revisar los logs integrados.

== Logs and Auditing ==

= ¿Dónde puedo ver el historial de acciones? =
En el menú ES Football Bypass for Cloudflare > Logs. Muestra las últimas ejecuciones automáticas (cron interno o externo) y las acciones manuales con fecha, detalle y usuario.

= ¿Puedo desactivar el registro de logs? =
Sí. En Ajustes > ES Football Bypass for Cloudflare puedes desactivar el registro o ajustar los días de retención (mínimo 1). Los logs se guardan en el directorio uploads, en `es-football-bypass-for-cloudflare/logs/`, protegidos con .htaccess.

= ¿Cómo verifico que el cron funciona correctamente? =
Puedes comprobar si está programado en Herramientas > Salud del sitio > Información > Eventos programados, buscando el evento 'cfbcolorvivo_check_football_status'. También puedes revisar los logs de errores de WordPress, donde el plugin registra todas sus acciones.

== Screenshots ==

1. Página de Configuración: selecciona el tipo de autenticación de Cloudflare (Global API Key, Token de usuario o Token de cuenta), introduce las credenciales, configura el intervalo de comprobación, el enfriamiento tras desactivar Cloudflare, el override "Forzar Proxy OFF durante fútbol", la retención de logs y el token de cron externo.
2. Página de Operación: estado en vivo de los bloqueos según hayahora.futbol, registros DNS en caché con el estado Proxied actual de cada uno, controles manuales (probar conexión, forzar Proxy ON/OFF, comprobación manual, diagnóstico WP-Cron) y barra lateral con enlaces relacionados.

== Changelog ==

= 1.9.1 =
* FIX: Text domain cambiado para coincidir con el nuevo slug de WP.org (es-football-bypass-for-cloudflare)
* FIX: Todas las rutas de fichero ahora usan wp_upload_dir() en lugar de WP_CONTENT_DIR hardcodeado
* FIX: Operaciones de fichero migradas a la API WP_Filesystem (no más file_put_contents)
* FIX: register_setting() usa el formato correcto de array con sanitize_callback
* FIX: Saneamiento más estricto para selected_records, bypass_blocked_ips y campos de estado
* FIX: El JavaScript inline ya no usa interpolación PHP, usa datos de wp_localize_script
* FIX: El directorio de datos del plugin se ha renombrado a es-football-bypass-for-cloudflare en uploads
* FIX: Campo Contributors corregido en readme.txt
* DOCS: Sección External services actualizada con enlaces de información de hayahora.futbol

= 1.9.0 =
* RENAME: Plugin renombrado de "CF Football Bypass" a "ES Football Bypass for Cloudflare" (cumplimiento de marcas registradas en WordPress.org)
* DOCS: Sección External services ampliada con la documentación de los servicios de detección de IP del servidor
* DOCS: Detalles de privacidad y transmisión de datos mejorados para todos los servicios externos

= 1.8.6 =
* CODE: Cumplimiento completo de WordPress Coding Standards (PHPCS): tabs, espaciado, condiciones Yoda, variables snake_case, comentarios PHPDoc
* UX: La versión del plugin ahora se muestra en todas las páginas del plugin (Operación, Ajustes, Logs)
* I18N: Todas las cadenas hardcodeadas en español restantes envueltas en __() para traducciones consistentes
* CODE: Operadores ternarios cortos reemplazados por ternarios completos según los estándares de WP
* CODE: Las llamadas a in_array() ahora usan modo estricto
* CODE: Refactorizados los patrones de asignación dentro de condición

= 1.8.5 =
* NEW: Soporte para Cloudflare Account-owned API Tokens (además de los User API Tokens y la Global API Key)
* NEW: Campo Account ID mostrado cuando se selecciona Account Token
* UX: El selector de tipo de autenticación ofrece ahora tres opciones: Global API Key, User Token, Account Token
* UX: Los campos de email y Account ID se muestran/ocultan dinámicamente según el tipo de autenticación seleccionado

= 1.8.2 =
* NEW: Detección de la IP de salida del servidor mostrada en Ajustes para ayudar a restringir el API Token de Cloudflare por IP
* UX: La IP se cachea durante 1 hora y se detecta desde varias fuentes para mayor fiabilidad

= 1.8.1 =
* SECURITY: La comparación del token de cron externo ahora usa hash_equals() para prevenir ataques de timing
* PERFORMANCE: La poda de logs se limita a una vez al día en lugar de en cada evento de log
* UX: Diálogos de confirmación antes de las acciones destructivas (Force OFF, Force ON, Reset)
* UX: Los botones de acción se desactivan durante las operaciones AJAX para prevenir doble clic
* UX: Detección de entorno local con aviso amigable en la página de Operación
* CODE: Añadido uninstall.php para limpieza completa al desinstalar (WP_Filesystem)
* CODE: Reemplazado current_time('timestamp') (deprecado) por time() (WP 5.3+)

= 1.8.0 =
* IMPROVEMENT: Cambiados todos los prefijos de cfb_ a cfbcolorvivo_ para evitar conflictos con otros plugins
* IMPROVEMENT: Cambiados todos los identificadores CSS/JS de cfb- a cfbcolorvivo- para mayor unicidad
* CODE: Opción de ajustes renombrada a cfbcolorvivo_settings
* CODE: Hook de cron renombrado a cfbcolorvivo_check_football_status
* CODE: Directorio de logs renombrado a cfbcolorvivo-logs
* CODE: Todas las acciones AJAX, transients y filtros actualizados con el nuevo prefijo

= 1.7.1 =
* FIX: Corregido bug crítico en los checkboxes de configuración que impedía desmarcar opciones una vez activadas
* FIX: La opción "Forzar Proxy OFF durante fútbol" ahora puede desactivarse correctamente
* FIX: La opción "Registro de acciones" ahora puede desactivarse correctamente
* FIX: Mejorado el cumplimiento del código con las directrices de plugins de WordPress.org

= 1.7.0 =
* IMPROVEMENT: JavaScript ahora usa wp_enqueue_script() y wp_add_inline_script() según las directrices del directorio de WordPress.org
* IMPROVEMENT: Eliminados todos los bloques de script inline del código PHP
* IMPROVEMENT: Datos dinámicos pasados vía wp_localize_script() para una mejor separación del código
* IMPROVEMENT: Hook admin_enqueue_scripts implementado correctamente con filtrado por página
* CODE: Refactorización completa del sistema de assets de admin

= 1.6.0 =
* SECURITY: Fichero de log movido a wp-content/uploads/cfbcolorvivo-logs/ con protección .htaccess
* SECURITY: Anonimización de IPs en los logs para cumplimiento de RGPD
* SECURITY: Eliminados los operadores de supresión de errores (@) con comprobaciones explícitas
* SECURITY: Añadidos ficheros index.php para prevenir el listado de directorios
* IMPROVEMENT: Soporte completo de internacionalización (i18n) con el text domain cf-football-bypass
* IMPROVEMENT: Cabecera del plugin actualizada con todos los campos requeridos por WordPress.org
* IMPROVEMENT: Creación automática del directorio de logs con protección
* IMPROVEMENT: Mejor manejo de errores en la escritura de ficheros
* FIX: Sincronización de versión entre la cabecera del plugin y readme.txt

= 1.0.1 =
* Añadido soporte para API Token de Cloudflare
* Botón de control manual mejorado con confirmación
* Barra lateral con enlaces recomendados
* Correcciones menores de bugs
* Mejor manejo de errores y logs

= 1.0.0 =
* Versión inicial
* Monitorización automática de hayahora.futbol
* Gestión automática de registros DNS de Cloudflare
* Soporte de Global API Key
* Panel de administración
* Sistema de cron integrado

== Upgrade Notice ==

= 1.9.1 =
Cumplimiento de la revisión de WP.org: text domain, rutas de fichero, WP_Filesystem, saneamiento y correcciones de escapado en JS. Ficheros de idioma renombrados para coincidir con el nuevo slug.

= 1.9.0 =
Plugin renombrado a "ES Football Bypass for Cloudflare" para cumplir con las marcas registradas de WordPress.org. Documentación de servicios externos ampliada.

= 1.8.6 =
Release de calidad de código: cumplimiento completo de WordPress Coding Standards, versión del plugin mostrada en todas las páginas, y consistencia mejorada de i18n.

= 1.8.5 =
Nuevo: Soporte para Cloudflare Account-owned API Tokens. Ahora puedes usar tokens de Manage Account > Account API Tokens además de tokens de usuario y la Global API Key.

= 1.8.2 =
Nuevo: Muestra la IP de salida del servidor en Ajustes para que puedas restringir tu API Token de Cloudflare a esa IP por seguridad adicional.

= 1.8.1 =
Mejoras de seguridad y usabilidad: comparación de tokens segura ante timing, diálogos de confirmación, anti doble clic, detección de entorno local, y limpieza correcta al desinstalar.

= 1.8.0 =
Actualización de prefijos: todos los prefijos internos cambiados de cfb_ a cfbcolorvivo_ para evitar conflictos entre plugins. Los ajustes existentes se migrarán automáticamente.

= 1.7.1 =
Corrección importante: los checkboxes de configuración funcionan correctamente. Actualización recomendada si usas la opción "Forzar Proxy OFF durante fútbol".

= 1.7.0 =
Cumplimiento de las directrices de WordPress.org: JavaScript ahora se carga correctamente usando wp_enqueue_script() y wp_add_inline_script() en lugar de bloques de script inline.

= 1.6.0 =
Versión preparada para el directorio de WordPress.org. Incluye importantes mejoras de seguridad: logs protegidos, IPs anonimizadas y soporte de traducciones.

= 1.0.1 =
Esta versión añade soporte para API Token de Cloudflare (más seguro que la Global API Key) y mejora el control manual del bypass con confirmaciones de seguridad.

== Server Requirements ==

- WordPress 5.0 o superior
- PHP 7.4 o superior
- Extensiones PHP: curl, json
- Permisos: capacidad de hacer peticiones HTTP salientes
- Cron: sistema de cron de WordPress funcional

== Support ==

- Autor: David Carrero Fernandez-Baillo
- Sitio web: https://carrero.es
- Contacto: https://carrero.es/contacto/

Si necesitas ayuda, envía un mensaje directo en X o usa el formulario de contacto. Issues y mejoras también son bienvenidas en el repositorio: https://github.com/dcarrero/cf-football-bypass

Este plugin nació de la necesidad real de proteger sitios web legítimos de los bloqueos masivos que afectan a la industria digital española durante los eventos deportivos.

== Specific Use Cases ==

Sitios de alto tráfico
- Permite seleccionar solo los registros críticos (www, dominio raíz)
- Mantiene otros servicios (mail, ftp, etc.) siempre proxied
- Minimiza el impacto en CDN y caché

Sitios con múltiples subdominios
- Control granular por subdominio
- Estrategias diferentes para servicios diferentes
- Flexibilidad total de configuración

Emergencias y override manual
- Botones de control manual para situaciones especiales
- No depende únicamente de la detección automática
- Permite reaccionar rápidamente ante fallos

== License ==

GPLv2 o posterior. Eres libre de usar, modificar y distribuir este plugin bajo los términos de la GPL.
