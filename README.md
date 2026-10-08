# CIMD MCP reference server

A remote MCP server on Cloudflare Workers that accepts OAuth clients identified by a Client ID Metadata Document (CIMD). It is for MCP server developers who want clients to connect without a developer portal or pre-registration.

Explainer page: https://andreagriffiths11.github.io/cimd-mcp-reference/

[Español](README.es.md)

## Try the live demo

The demo runs at https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/mcp. It has no password.

Run MCP Inspector against it:

```bash
npx @modelcontextprotocol/inspector --server-url https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/mcp --transport http --client-metadata-url https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/examples/inspector-web.json
```

Inspector opens in your browser. Connect, and the server shows a consent screen for "MCP Inspector (web)". Click Allow. Inspector gets a token and lists four tools: `whoami`, `current_time`, `add_note`, `list_notes`.

Tokens from the demo only reach these demo tools and demo notes.

## How CIMD works here

1. The client calls `/mcp` without a token and gets a 401. The `WWW-Authenticate` header points to the protected resource metadata (RFC 9728).
2. The client reads that metadata, then the authorization server metadata (RFC 8414). It advertises `client_id_metadata_document_supported: true` and PKCE `S256`.
3. The client sends its `client_id` to `/authorize`. The `client_id` is an HTTPS URL to a JSON document that lists the client's name and redirect URIs.
4. The server fetches that document, checks that its `client_id` equals the URL, and checks the `redirect_uri` against its list. The fetch has SSRF guards.
5. The user approves on the consent screen. The client exchanges the code at `/token` with its PKCE verifier and the `resource` parameter (RFC 8707).
6. The access token is bound to `/mcp` on this server. The client uses it to call tools.

Dynamic Client Registration (RFC 7591) is deprecated in the MCP spec. It is off by default here.

This is a teaching demo. It has one demo user and no real login.

## Run it locally

Requires Node.js 20.11 or newer.

```bash
npm install
```

```bash
npm run dev
```

In a second terminal:

```bash
node examples/client/cimd-client.mjs
```

The server runs at http://localhost:8787. The example client hosts its own metadata document on loopback, opens the consent screen in your browser, gets a token, and calls the tools.

Run the type check and tests:

```bash
npm run check
```

## Deploy your own copy

Log in to Cloudflare:

```bash
npx wrangler login
```

Set `ISSUER` in `wrangler.jsonc` to your Worker's URL, for example `https://cimd-mcp-reference.<your-subdomain>.workers.dev`. Then deploy:

```bash
npm run deploy
```

To require a password on the consent screen, set the optional `CONSENT_PASSWORD` secret:

```bash
npx wrangler secret put CONSENT_PASSWORD
```

A real server should use real user login.

## More detail

- [docs/reference.md](docs/reference.md): endpoints, CIMD rules, tokens, configuration
- [docs/clients.md](docs/clients.md): MCP Inspector, Claude, Cursor, and other clients
- [docs/security.md](docs/security.md): SSRF guards, token binding, consent screen

MIT license. By [Andrea Griffiths](https://github.com/AndreaGriffiths11).
