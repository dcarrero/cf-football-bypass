=== CF Football Bypass ===
Contributors: davidcarrero
Tags: cloudflare, dns, football, bypass, laliga, ip-blocking
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: cf-football-bypass
Domain Path: /languages

Gestiona automaticamente la configuracion de Cloudflare durante los partidos de futbol para evitar bloqueos de IPs masivos.

== Description ==

CF Football Bypass es un plugin de WordPress creado por David Carrero Fernandez-Baillo para ayudar a sitios espanoles a capear los bloqueos masivos de IPs que ordena LaLiga durante los partidos de futbol. El proyecto es libre (GPLv2) y su codigo fuente esta disponible en GitHub: https://github.com/dcarrero/cf-football-bypass

El plugin monitoriza automaticamente los eventos futbolisticos en Espana consultando hayahora.futbol y, en funcion del resultado, gestiona los registros DNS de Cloudflare para alternar entre modo proxied y DNS Only. Asi se evita que los visitantes legitimos caigan en los bloqueos judiciales dirigidos contra el futbol pirata.

= Problema que resuelve =

En Espana, durante los partidos de futbol, se producen bloqueos masivos de IPs y rangos de IPs por ordenes judiciales para combatir el futbol pirata. Estos bloqueos afectan tambien a sitios web legitimos que nada tienen que ver con el futbol, causando perdidas de trafico y facturacion.

= Solucion =

Cuando se detecta que hay futbol:
- Desactiva automaticamente el proxy de Cloudflare para los registros DNS seleccionados
- Tu sitio web pasa a usar DNS Only, evitando las IPs de Cloudflare que pueden estar bloqueadas
- Despues del tiempo configurado, reactiva automaticamente el proxy de Cloudflare

= Caracteristicas principales =

Automatizacion completa
- Monitorizacion automatica cada X minutos (configurable 5-60 min)
- Activacion/desactivacion automatica del bypass
- Sistema de cron integrado en WordPress

Soporte dual de autenticacion Cloudflare
- API Key Global (tradicional)
- Token API con permisos especificos (mas seguro)

Control granular
- Seleccion especifica de registros DNS (A, AAAA y CNAME)
- Duracion configurable del bypass (60-600 minutos)
- Intervalo personalizable tras desactivar Cloudflare antes de reintentar activarlo
- Control manual para casos especiales

Dashboard informativo
- Estado actual del futbol en tiempo real
- Ultima comprobacion realizada
- Estado del bypass (activo/inactivo)

Herramientas adicionales
- Boton de test de conexion con Cloudflare
- Comprobacion manual del estado de futbol
- Botones de activacion/desactivacion manual
- Logs detallados para debugging y auditoria (cron, acciones manuales)
- Endpoint protegido para cron externo

== Installation ==

1. Descarga e instalacion
   - Descarga el archivo zip del plugin
   - Descomprime (o sube la carpeta resultante) en `wp-content/plugins/cf-football-bypass/`
   - Ve a tu panel de WordPress > Plugins > CF Football Bypass > Activar

2. Configuracion de Cloudflare
   - Ve a Ajustes > CF Football Bypass
   - Selecciona tu tipo de autenticacion (API Key Global o Token API)
   - Introduce tus credenciales de Cloudflare
   - Anade el Zone ID de tu dominio

3. Configuracion del plugin
   - Establece el intervalo de comprobacion (recomendado: 15 minutos)
   - Ajusta el intervalo tras desactivar Cloudflare (cooldown) si necesitas mas o menos tiempo (por defecto 60 minutos)
   - Define la duracion del bypass (recomendado: 120 minutos)
   - Haz clic en "Probar conexion y actualizar lista DNS"
   - Selecciona los registros DNS que quieres gestionar
   - Guarda la configuracion

= Obtener credenciales de Cloudflare =

Para API Key Global:
1. Ve a Cloudflare > Mi perfil > Tokens API
2. En "API Keys", copia tu "Global API Key"
3. Necesitaras tambien tu email de la cuenta

Para Token API (recomendado):
1. Ve a Cloudflare > Mi perfil > Tokens API
2. Haz clic en "Crear token"
3. Usa la plantilla "Personalizado"
4. Permisos necesarios:
   - Zone:Read (para leer la informacion de zona)
   - DNS:Read (para listar registros DNS)
   - DNS:Edit (para modificar el estado del proxy)

== External Services ==

Este plugin se conecta a los siguientes servicios externos:

= hayahora.futbol =
El plugin consulta periodicamente el endpoint https://hayahora.futbol/estado/data.json para obtener informacion sobre bloqueos de IPs activos durante eventos de futbol en Espana. Este servicio es gratuito y de codigo abierto.
- URL: https://hayahora.futbol/
- Politica de privacidad: El servicio no recopila datos personales de los usuarios del plugin.

= Cloudflare API =
El plugin utiliza la API oficial de Cloudflare (https://api.cloudflare.com/client/v4/) para gestionar los registros DNS de tu zona. Requiere credenciales de API que tu proporcionas.
- URL: https://api.cloudflare.com/
- Terminos de servicio: https://www.cloudflare.com/terms/
- Politica de privacidad: https://www.cloudflare.com/privacypolicy/

= Enlaces de afiliados =
La pagina de operacion del plugin incluye enlaces de afiliado claramente marcados con "(aff)" hacia servicios VPN y herramientas de seguridad. Estos enlaces son opcionales y no afectan la funcionalidad del plugin.

== Frequently Asked Questions ==

= Es seguro usar este plugin? =
Si. El plugin solo modifica el estado del proxy de Cloudflare (Proxied/DNS Only) para los registros que selecciones. No elimina ni modifica el contenido de los registros DNS.

= Que pasa si falla la deteccion de futbol? =
En caso de error al consultar hayahora.futbol, el plugin asume que NO hay futbol por seguridad, manteniendo el estado actual sin realizar cambios.

= Puedo usar esto con cualquier proveedor DNS? =
No, este plugin esta disenado especificamente para trabajar con Cloudflare. Necesitas que tus DNS esten gestionados por Cloudflare.

= Afecta al SEO de mi web? =
No deberia afectar negativamente. El plugin solo cambia temporalmente si tu sitio pasa por el proxy de Cloudflare o no. El contenido y las URLs permanecen iguales.

= Que ocurre si desactivo el plugin durante un bypass activo? =
Al desactivar el plugin, se ejecuta automaticamente una funcion que reactiva el proxy de Cloudflare para todos los registros seleccionados.

= Puedo controlar manualmente el bypass? =
Si, el plugin incluye botones para:
- Comprobar manualmente el estado de futbol
- Forzar la activacion/desactivacion del bypass
- Test de conexion con Cloudflare

= Que tipos de registro DNS soporta? =
Actualmente soporta registros tipo A y CNAME, que son los mas comunes y los que se ven afectados por los bloqueos de IP.

= Como funciona el sistema de cron? =
Consulta la seccion "Cron y automatizacion" para ver como funciona wp_cron, el endpoint externo y las recomendaciones de configuracion.

== Cron y automatizacion ==

= Como funciona el sistema de cron? =
El plugin utiliza el cron interno de WordPress (wp_cron) que se ejecuta cuando hay visitas al sitio web. Normalmente esto es suficiente para la mayoria de sitios.

= Que hago si mi sitio tiene poco trafico y el cron no se ejecuta regularmente? =
Ve a Ajustes > CF Football Bypass y copia el token del apartado "Cron externo". Con ese token puedes programar un cron real del servidor:

*/15 * * * * curl -s "https://tudominio.com/wp-cron.php?cfb_cron=1&token=TOKEN_AQUI" > /dev/null 2>&1

Puedes regenerar el token borrando el campo y guardando los ajustes (se genera uno nuevo). Este endpoint solo ejecuta la comprobacion del plugin, sin depender de visitas.

= Que es el "Intervalo tras desactivar Cloudflare"? =
Es el tiempo de espera (por defecto 60 minutos) que el plugin respeta antes de volver a revisar si puede activar Cloudflare tras haber detectado un bloqueo. Durante este periodo el proxy se mantiene en "DNS Only" aunque el JSON deje de marcar el dominio, evitando ciclos de activacion/desactivacion rapidos.

= Como verifico que el cron funciona correctamente? =
En la pestaña Operacion pulsa "Diagnostico WP-Cron" para ver proxima ejecucion y el resultado del ultimo check. Tambien puedes revisar los logs integrados.

== Logs y auditoria ==

= Donde veo el historico de acciones? =
En el menu CF Football Bypass > Logs. Muestra las ultimas ejecuciones automaticas (cron interno o externo) y las acciones manuales con fecha, detalle y usuario.

= Puedo desactivar los logs? =
Si. En Ajustes > CF Football Bypass puedes desactivar el registro o ajustar los dias de retencion (minimo 1). Los logs se guardan en `wp-content/uploads/cfb-logs/cfb-actions.log` protegidos con .htaccess.

= Como verifico que el cron funciona correctamente? =
Puedes comprobar si esta programado en Herramientas > Salud del sitio > Info > Eventos programados, buscando el evento 'cfb_check_football_status'. Tambien puedes revisar los logs de error de WordPress donde el plugin registra todas sus acciones.

== Changelog ==

= 1.7.0 =
* MEJORA: Scripts JavaScript ahora usan wp_enqueue_script() y wp_add_inline_script() segun las directrices del directorio de WordPress.org
* MEJORA: Eliminados todos los bloques <script> inline del codigo PHP
* MEJORA: Datos dinamicos pasados via wp_localize_script() para mejor separacion de codigo
* MEJORA: Hook admin_enqueue_scripts implementado correctamente con filtrado por pagina
* CODIGO: Refactorizacion completa del sistema de assets de admin

= 1.6.0 =
* SEGURIDAD: Archivo de logs movido a wp-content/uploads/cfb-logs/ con proteccion .htaccess
* SEGURIDAD: Anonimizacion de IPs en logs para cumplimiento GDPR
* SEGURIDAD: Eliminados operadores de supresion de errores (@) por verificaciones explicitas
* SEGURIDAD: Anadidos archivos index.php para prevenir listado de directorios
* MEJORA: Soporte completo de internacionalizacion (i18n) con text domain cf-football-bypass
* MEJORA: Header del plugin actualizado con todos los campos requeridos por WordPress.org
* MEJORA: Creacion automatica de directorio de logs con proteccion
* MEJORA: Mejor manejo de errores en escritura de archivos
* FIX: Sincronizacion de version entre plugin header y readme.txt

= 1.0.1 =
* Anadido soporte para Token API de Cloudflare
* Mejorado el boton de control manual con confirmacion
* Sidebar con enlaces recomendados
* Correccion de bugs menores
* Mejor manejo de errores y logs

= 1.0.0 =
* Version inicial
* Monitorizacion automatica de hayahora.futbol
* Gestion automatica de registros DNS de Cloudflare
* Soporte para API Key Global
* Dashboard de administracion
* Sistema de cron integrado

== Upgrade Notice ==

= 1.7.0 =
Cumplimiento de directrices WordPress.org: JavaScript ahora se carga correctamente usando wp_enqueue_script() y wp_add_inline_script() en lugar de bloques script inline.

= 1.6.0 =
Version preparada para el directorio de WordPress.org. Incluye mejoras de seguridad importantes: logs protegidos, IPs anonimizadas, y soporte de traducciones.

= 1.0.1 =
Esta version anade soporte para Token API de Cloudflare (mas seguro que API Key Global) y mejora el control manual del bypass con confirmaciones de seguridad.

== Requisitos del servidor ==

- WordPress 5.0 o superior
- PHP 7.4 o superior  
- Extensiones PHP: curl, json
- Permisos: Capacidad de hacer peticiones HTTP salientes
- Cron: Sistema de cron de WordPress funcional

== Soporte ==

- Autor: David Carrero Fernandez-Baillo
- Web: https://carrero.es
- Contacto: https://carrero.es/contacto/

Si necesitas ayuda, escribe por mensaje directo en X o utiliza el formulario de contacto. Las issues y mejoras tambien son bienvenidas en el repositorio: https://github.com/dcarrero/cf-football-bypass

Este plugin nace de la necesidad real de proteger sitios web legitimos ante los bloqueos masivos que afectan a la industria digital espanola durante eventos deportivos.

== Casos de uso especificos ==

Sitios de alto trafico
- Permite seleccionar solo registros criticos (www, dominio raiz)
- Mantiene otros servicios (mail, ftp, etc.) siempre proxied
- Minimiza el impacto en CDN y cache

Sitios con subdominios multiples
- Control granular por subdominio
- Diferentes estrategias para diferentes servicios
- Flexibilidad total en la configuracion

Emergencias y override manual
- Botones de control manual para situaciones especiales
- No depende unicamente de la deteccion automatica
- Permite reaccion rapida ante fallos

== Licencia ==

GPLv2 o posterior. Eres libre de usar, modificar y distribuir este plugin segun los terminos de la GPL.
