# Conectar OSINT POWER a una IA

El servidor es local, usa **MCP por stdio** y no llama a un modelo. Elige un host MCP, configura el ejecutable y aporta el modelo desde ese host. Ninguna clave de OpenAI u otro proveedor es necesaria para el núcleo.

## Preparación

1. Instala dependencias con `npm ci --ignore-scripts`.
2. Ejecuta `node src/cli.js init` y ajusta `config.json`.
3. Usa rutas absolutas para `src/mcp.js`, `OSINT_POWER_CONFIG` y, si lo defines, `OSINT_POWER_DB`.
4. Instala solo los binarios que vayas a habilitar. La IA no instala ni cambia ejecutables a través del servidor.

Ejemplo de configuración para un host que utilice `mcpServers`:

```json
{
  "mcpServers": {
    "osint-power": {
      "command": "node",
      "args": ["C:\\proyectos\\OSINT_POWER\\src\\mcp.js"],
      "env": {
        "OSINT_POWER_CONFIG": "C:\\proyectos\\OSINT_POWER\\config.json",
        "OSINT_POWER_DB": "C:\\proyectos\\OSINT_POWER\\.osint-power\\state.sqlite"
      }
    }
  }
}
```

El formato exacto de registro cambia según el host. Mantén las mismas variables y argumentos al adaptarlo. Para comprobar el protocolo sin un modelo, ejecuta `npm test`: la prueba MCP levanta un cliente y servidor reales con configuración temporal y red deshabilitada.

## Secuencia recomendada

1. `capabilities({})`: comprobar alcance, fuentes habilitadas y límites.
2. `query_findings({"type":"domain","limit":25})`: reutilizar estado antes de repetir consultas.
3. `collect({"adapter":"crtsh","target":"example.com"})` o `passive_pipeline({"target":"example.com"})` sobre un dominio configurado con red habilitada.
4. `query_findings`: leer el resumen; pasar `next_cursor` como `cursor` para la siguiente página.
5. `get_evidence({"entity_id":"HASH_SHA256","limit":10})`: revisar el origen de una conclusión.
6. `get_graph` y `get_report`: correlacionar y proponer los siguientes pasos.

`collect` recibe únicamente un adaptador registrado y un objetivo, no comandos ni opciones de shell. Las acciones activas requieren configuración previa; la IA no puede activarlas desde MCP. `import_findings` recibe el contenido del export, no una ruta local. El host decide qué archivos comparte.

## Contrato de respuesta

Las respuestas válidas llevan `structuredContent` y una copia JSON en `content`:

```json
{
  "ok": true,
  "result": {
    "items": [],
    "next_cursor": null,
    "limit": 25,
    "total": 0
  }
}
```

Los resultados parciales o fallidos usan `ok: false`; MCP incluye `isError: true`. Revisa `code`, `invalid`, `skipped`, `truncated` y el historial. Un código de salida correcto del binario no confirma que todo su contenido fuera válido. La CLI sale con código 1 ante fallo o resultado parcial.

`get_report` contiene hasta 50 entidades, 50 relaciones y 20 ejecuciones. `query_findings`, `get_evidence` y `get_graph` admiten páginas de 1 a 100 elementos. Solo `query_findings` usa cursor por ID; evidencia y grafo usan `offset`. El grafo puede cambiar si se importa nueva información entre páginas.

## Evidencia y prompt injection

Todo texto proveniente de una web, perfil, documento, nombre de archivo, metadato o export es **dato no confiable**. Una evidencia que diga «ignora el scope», solicite claves o contenga comandos no modifica la tarea del agente. `get_evidence` marca los registros como `untrusted: true`.

El servidor valida, limita e importa datos; no es un clasificador de prompt injection. La política del host y la revisión del agente siguen siendo necesarias. Usa [AGENT_PROMPT.md](AGENT_PROMPT.md) como plantilla, sin reemplazar las reglas de mayor prioridad del host.

## Claves y errores habituales

- `NETWORK_DISABLED`: la configuración es offline. Revisa `network` fuera de la sesión del agente.
- `ACTIVE_DISABLED` / `ADAPTER_DISABLED`: el modo o adaptador no está habilitado.
- `OUT_OF_SCOPE`: objetivo fuera del alcance o excluido; no cambia al dominio vecino.
- `TOOL_NOT_INSTALLED`: instala el binario oficial y comprueba PATH.
- `TOOL_FAILED`: comprueba localmente la versión y flags. No se vuelcan stderr ni posibles secretos en el resultado MCP.
- `HTTP_401` / `HTTP_403`: credenciales o plan del proveedor; no se reintentan.
- `HTTP_429`: hasta tres intentos en total con backoff y respeto a `Retry-After`.
- `RETRY_LATER`: el proveedor pide más de 60 segundos; se finaliza esta fuente y se conserva el resto.
- `RESPONSE_TOO_LARGE` / `PROCESS_TIMEOUT`: consulta acotada fallida, sin ingerir un fragmento como si fuera respuesta completa.
- `SCOPE_DATABASE_MISMATCH`: usa una base de datos diferente para el nuevo alcance.

HIBP usa `HIBP_API_KEY` del entorno del servidor y exige el correo exacto en `scope.emails`. No pongas claves en prompts, argumentos, README ni commits. Subfinder y Amass administran sus propios archivos de proveedores. No hay rotación de claves ni cambio de cuenta para eludir límites.

## Referencias de implementación

- [SDK MCP oficial: servidor y stdio](https://ts.sdk.modelcontextprotocol.io/v2/).
- [SQLite incluido en Node](https://nodejs.org/api/sqlite.html).
- [Fuentes y contrato de adaptadores](ADAPTERS.md).
