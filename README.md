# ES Football Bypass for Cloudflare

**Versión 1.9.0** | [Changelog](readme.txt)

Plugin de WordPress que automatiza el cambio entre modo Proxied y DNS Only en Cloudflare cuando hay bloqueos masivos ordenados durante los partidos de fútbol en España. Consulta el feed de [hayahora.futbol](https://hayahora.futbol/) y activa/desactiva los registros seleccionados para mantener accesible tu sitio legítimo, con un periodo de enfriamiento configurable antes de volver a activar Cloudflare.

## Instalación rápida

1. Descarga el ZIP desde [GitHub](https://github.com/dcarrero/cf-football-bypass).
2. Sube la carpeta `es-football-bypass` a `wp-content/plugins/` (quedará como `plugins/es-football-bypass/`).
3. Activa el plugin desde *Plugins > Plugins instalados*.
4. Configura tus credenciales Cloudflare en *Ajustes > ES Football Bypass*, ajusta el intervalo de comprobación y el cooldown tras desactivar Cloudflare, y selecciona los registros DNS a gestionar.

## Autor y soporte

- Autor: [David Carrero Fernandez-Baillo](https://carrero.es)
- Sitio web: https://carrero.es
- Contacto rápido: https://carrero.es/contacto/

Más detalles, preguntas frecuentes y guía ampliada en el fichero [readme.txt](readme.txt).
