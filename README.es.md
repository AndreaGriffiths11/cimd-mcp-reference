# Servidor MCP de referencia con CIMD

Un servidor MCP remoto en Cloudflare Workers que acepta clientes OAuth identificados por un Client ID Metadata Document (CIMD). Es para desarrolladores de servidores MCP que quieren que los clientes se conecten sin un portal de desarrolladores ni registro previo.

Página explicativa: https://andreagriffiths11.github.io/cimd-mcp-reference/?lang=es

[English](README.md)

## Prueba la demo en vivo

La demo corre en https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/mcp. No tiene contraseña.

Ejecuta MCP Inspector contra ella:

```bash
npx @modelcontextprotocol/inspector --server-url https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/mcp --transport http --client-metadata-url https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/examples/inspector-web.json
```

Inspector se abre en tu navegador. Conéctate y el servidor muestra una pantalla de consentimiento para "MCP Inspector (web)". Haz clic en Allow. Inspector recibe un token y lista cuatro herramientas: `whoami`, `current_time`, `add_note`, `list_notes`.

Los tokens de la demo solo llegan a estas herramientas y a las notas de demostración.

## Cómo funciona CIMD aquí

1. El cliente llama a `/mcp` sin token y recibe un 401. El encabezado `WWW-Authenticate` apunta a los metadatos del recurso protegido (RFC 9728).
2. El cliente lee esos metadatos y luego los del servidor de autorización (RFC 8414). Estos anuncian `client_id_metadata_document_supported: true` y PKCE `S256`.
3. El cliente envía su `client_id` a `/authorize`. El `client_id` es una URL HTTPS a un documento JSON con el nombre del cliente y sus URIs de redirección.
4. El servidor descarga ese documento, comprueba que su `client_id` sea igual a la URL y compara el `redirect_uri` con su lista. La descarga tiene protecciones contra SSRF.
5. El usuario aprueba en la pantalla de consentimiento. El cliente canjea el código en `/token` con su verificador PKCE y el parámetro `resource` (RFC 8707).
6. El token de acceso queda ligado a `/mcp` en este servidor. El cliente lo usa para llamar a las herramientas.

Dynamic Client Registration (RFC 7591) está obsoleto en la especificación MCP. Aquí está apagado por defecto.

Es una demo para aprender. Tiene un único usuario de demostración y no tiene login real.

## Ejecútalo en local

Requiere Node.js 20.11 o superior.

```bash
npm install
```

```bash
npm run dev
```

En una segunda terminal:

```bash
node examples/client/cimd-client.mjs
```

El servidor corre en http://localhost:8787. El cliente de ejemplo publica su propio documento de metadatos en loopback, abre la pantalla de consentimiento en tu navegador, recibe un token y llama a las herramientas.

Ejecuta la verificación de tipos y las pruebas:

```bash
npm run check
```

## Despliega tu propia copia

Inicia sesión en Cloudflare:

```bash
npx wrangler login
```

Pon en `ISSUER` dentro de `wrangler.jsonc` la URL de tu Worker, por ejemplo `https://cimd-mcp-reference.<tu-subdominio>.workers.dev`. Luego despliega:

```bash
npm run deploy
```

Para pedir una contraseña en la pantalla de consentimiento, define el secreto opcional `CONSENT_PASSWORD`:

```bash
npx wrangler secret put CONSENT_PASSWORD
```

Un servidor real debería usar un login de usuario real.

## Más detalle

- [docs/reference.md](docs/reference.md): endpoints, reglas CIMD, tokens, configuración (en inglés)
- [docs/clients.md](docs/clients.md): MCP Inspector, Claude, Cursor y otros clientes (en inglés)
- [docs/security.md](docs/security.md): protecciones SSRF, tokens ligados, pantalla de consentimiento (en inglés)

Licencia MIT. De [Andrea Griffiths](https://github.com/AndreaGriffiths11).
