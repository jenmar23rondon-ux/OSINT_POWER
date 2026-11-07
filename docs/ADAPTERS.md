# Adaptadores y contratos

## Ejecución disponible

`src/adapters.js` define un registro cerrado. Los objetivos pasan por `Scope.target` antes de construir argumentos; el cliente no puede proporcionar ejecutables, flags, URLs de proveedor ni comandos de shell.

| Adaptador | Contrato usado                                                                                            |
| --------- | --------------------------------------------------------------------------------------------------------- |
| crtsh     | GET a `https://crt.sh/`, array JSON, campo `name_value`                                                   |
| subfinder | `-d TARGET -silent -rl RATE -timeout SECONDS -duc`                                                        |
| amass     | `enum -passive -nocolor -d TARGET`, interfaz heredada documentada                                         |
| dnsx      | Un host por stdin, `-json -a -aaaa -rl RATE -t 1 -retry 1 -duc`                                           |
| httpx     | Un host por stdin, `-json -status-code -tech-detect -rl RATE -threads 1 -timeout SECONDS -retries 0 -duc` |
| naabu     | `-host TARGET -p PORTS -scan-type c -rate RATE -c 1 -retries 1 -json -duc`                                |
| hibp      | `/api/v3/breachedaccount/ACCOUNT?truncateResponse=true`, solo nombres de brechas                          |

Se añaden flags de salida silenciosa donde corresponde. Los límites nativos dependen de la versión; comprueba `--help` de tus binarios. Las pruebas del repositorio validan construcción y manejo del proceso, no equivalen a una certificación de todos los binarios upstream. Amass no expone un límite HTTP universal en esta interfaz: configura sus proveedores y usa el timeout del proceso. No lo habilites si necesitas un límite por fuente que tu versión no pueda imponer.

Los subprocessos no usan shell, ocultan la ventana en Windows y reciben una lista acotada de variables del sistema para PATH, temporales y configuración del usuario. El núcleo no inspecciona el contenido de los archivos de credenciales upstream. Los intentos se serializan por proceso del servidor; varios servidores o herramientas independientes necesitan coordinación externa.

## Importadores

```bash
node src/cli.js import --adapter sherlock --file researcher.csv
node src/cli.js import --adapter exiftool --file metadata.json
node src/cli.js import --adapter gitleaks --file leaks.json
node src/cli.js import --adapter jsonl --file findings.jsonl
```

- **subfinder / amass:** un nombre por línea o JSONL con `host`/`name`; `source` se conserva como `upstream`. No interpreta salidas de grafos completos de Amass.
- **dnsx:** JSON/JSONL con `host`, `a`, `aaaa`.
- **httpx:** JSON/JSONL con `url`, `status_code`, `tech`.
- **naabu:** JSON/JSONL con `host` o `ip` y `port`.
- **sherlock:** CSV con `username,name,url_main,url_user,exists,http_status,response_time_s`; solo filas `exists=Claimed`. El `--dump-response` de Sherlock es salida de depuración HTTP, no un export JSON.
- **theharvester:** objeto JSON con listas `emails` y `hosts`. Las versiones que exporten otro esquema requieren un conversor.
- **exiftool:** array JSON de `exiftool -j archivo.pdf`; se compara el nombre base con `scope.documents`.
- **gitleaks:** array JSON con `File`, `StartLine`, `RuleID`. No se guardan `Secret`, `Match`, autor ni mensaje de commit.
- **recon-ng / spiderfoot:** puente con nuestro contrato de observación. Convierte el export nativo a JSONL antes de importar. No son wrappers ejecutables de esos frameworks.
- **jsonl:** array, objeto o líneas del JSON Schema de observación. Conserva un `source` explícito; confianza de importaciones genéricas limitada a 0.7.

Documentos con el mismo nombre base son indistinguibles en esta versión. Usa un workspace separado o nombres únicos para evitar mezclarlos. Revisa y minimiza los exports antes de compartirlos con un host de IA; el saneamiento no detecta cualquier secreto posible.

Ejemplo del puente:

```json
{
  "type": "domain",
  "value": "api.example.com",
  "source": "my-source",
  "confidence": 0.6,
  "timestamp": "2026-11-07T00:00:00.000Z",
  "evidence": { "upstream": "public-dataset" }
}
```

Se admiten solo claves de evidencia conocidas, con valores acotados. Las consultas y fragmentos de URL se eliminan. Ambigüedad relacionada con un host declarado:

```json
{
  "type": "unresolved",
  "value": "Contact format unclear",
  "source": "review",
  "confidence": 0.2,
  "timestamp": "2026-11-07T00:00:00.000Z",
  "evidence": {
    "host": "example.com",
    "reason": "Document contains an incomplete email"
  }
}
```

## Añadir una fuente

1. Define entradas estrictas en `src/schema.js`; nunca aceptes un comando arbitrario.
2. Añade el adaptador y su modo en el registro; fija el host del proveedor para APIs.
3. Devuelve texto acotado al parser, sin imprimir en stdout del servidor MCP.
4. Implementa un parser que produzca `Observation` y filtre por `Scope`.
5. Añade fixtures sanitizados para éxito, fallo, fuera de alcance, redirección, formato inesperado y rate limit.
6. Documenta formato, versión compatible, claves, cuotas, confianza y límites; actualiza la matriz del README.
7. Ejecuta tests, lint, schemas y auditoría de dependencias. Nunca uses objetivos externos en CI.

La cola conserva lo logrado por otras fuentes. Solo se reintentan errores HTTP transitorios (red, 429 y 5xx), hasta tres intentos **en total**. Los fallos de procesos no se relanzan automáticamente: su error puede representar una instalación incompatible, no una condición transitoria.

## Fuentes primarias

- [ProjectDiscovery: herramientas y formatos](https://projectdiscovery.io/open-source).
- [httpx: opciones oficiales](https://docs.projectdiscovery.io/opensource/httpx/usage).
- [naabu: opciones oficiales](https://docs.projectdiscovery.io/opensource/naabu/usage).
- [Amass: guía del usuario e interfaz enum](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md).
- [Sherlock: exportación CSV en el código oficial](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/sherlock.py).
- [HIBP: API, suscripciones y límites](https://haveibeenpwned.com/API/v3).
