# Alcance, datos y operación

Define un workspace por investigación y documenta activos, exclusiones y límites aplicables. Los permisos y condiciones dependen de la fuente, la plataforma y el contexto: que un dato sea público o una consulta sea pasiva no implica autorización universal para cualquier tratamiento.

## Reglas que aplica el código

- Un dominio configurado incluye sus subdominios. Las exclusiones también se aplican a descendientes y tienen prioridad.
- No se permiten confusiones de sufijo: `example.com.evil.invalid` no pertenece a `example.com`.
- IPs de destino: lista exacta, sin rangos CIDR en v0.1. Una IP encontrada en DNS puede guardarse como evidencia, pero no habilita su colección activa.
- Correo: dominio configurado o cuenta explícita para importaciones. HIBP requiere siempre cuenta exacta en `scope.emails`.
- Perfil: alias explícito en `scope.usernames`; se guarda como coincidencia inferida, sin confirmar identidad.
- Documentos/metadatos/posibles secretos: nombre base permitido en `scope.documents`.
- `unresolved`: solo con un host relacionado en scope. Los datos fuera de alcance se descartan y se cuentan.
- No se siguen redirecciones de APIs y httpx no recibe flags para seguirlas. Una redirección no autoriza el nuevo destino.

Los datos recibidos de binarios se filtran antes de almacenarse. Un binario upstream puede usar configuración propia o hacer peticiones internas que el wrapper no intercepta. Comprueba esa configuración y usa una política de salida de red si necesitas garantías de destino por conexión. El núcleo no es un firewall.

## Estado y privacidad

La base de datos, caché y configuración son locales y se excluyen de Git. No están cifradas. El historial registra adaptador, objetivo, tiempos, estado y resumen; las importaciones registran el hash del contenido. No se conserva el stdout/stderr crudo de herramientas.

El núcleo vincula la base de datos al scope inicial. Para un alcance diferente, elige otro `OSINT_POWER_DB` o `--db`; no reutilices datos de otro cliente. Haz copias de seguridad con el proceso detenido y aplica tu política de retención al workspace completo.

HIBP devuelve asociaciones con nombres de brechas, sin contraseñas. Gitleaks conserva ubicaciones y reglas, descartando campos de secretos. Antes de publicar evidencia revisa datos personales, archivos, rutas y exports. No subas bases SQLite, claves ni informes privados a issues.

## Límites de esta versión

No hay explotación, pruebas de validez de credenciales, búsqueda de contraseñas filtradas, acciones sobre cuentas, OCR de gafetes ni confirmación automática de identidad. Tampoco se hace scoring de personas. El proyecto ofrece observaciones para análisis de superficie e investigación; los resultados necesitan interpretación.

El contenedor limita el usuario del proceso; las cuotas de CPU/memoria y la política de red se establecen al ejecutarlo. Los binarios no se descargan automáticamente ni se consideran sandboxeados por llamarse desde Node.
