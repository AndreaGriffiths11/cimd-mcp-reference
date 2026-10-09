# Connecting clients

The MCP endpoint is `{issuer}/mcp`. Any client that follows MCP 2026-07-28 authorization, sends PKCE S256 and the `resource` parameter, and identifies itself with a CIMD URL will work.

To see which path a client uses, watch the wire: a CIMD client sends `client_id=https://...` to `/authorize`; a DCR client calls `POST /register` first.

## Example client (this repo)

```bash
node examples/client/cimd-client.mjs --server http://localhost:8787/mcp
```

Against a deployed Worker, host your own HTTPS metadata document and pass `--client-id https://your.example/client.json`. Its `redirect_uris` must include `http://127.0.0.1:8976/callback` (or the port you give with `--port`). The script still listens locally for the callback.

On Windows, the client prints the authorization URL instead of passing a server-controlled URL to a command shell. Open it manually. Other platforms open the browser automatically unless you pass `--no-browser`. Authorization endpoints must use HTTP or HTTPS.

Verified against local `wrangler dev` on 8 October 2026: CIMD fetch, consent, code + PKCE, audience-bound token, `whoami` / `add_note` / `list_notes`, refresh rotation.

## MCP Inspector

Inspector 2.x supports CIMD via `--client-metadata-url` ([authorization](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/authorization), [flags](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector/configuration)). Inspector requires that URL to be `https` with a non-root path, so a plain `http://localhost:8787/...` URL is rejected on the client side even though this server accepts it in development.

Against the live Worker:

```bash
npx @modelcontextprotocol/inspector \
  --server-url https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/mcp \
  --transport http \
  --client-metadata-url https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/examples/inspector-web.json
```

The Worker serves that document with `client_id` equal to its own URL and the Inspector web default redirect. For the CLI or TUI use `/examples/inspector-cli.json`. When `client_id` is this Worker's own example URL, authorization builds the document in-process (a Worker cannot `fetch()` its own `workers.dev` hostname) and still runs the same CIMD validators. Third-party `client_id` URLs are still fetched over the network.

Against local `wrangler dev`: either put a Cloudflare Tunnel in front so both the issuer and the metadata URL are HTTPS, or host `examples/cimd/inspector-web.json` at any HTTPS URL, set its `client_id` to that URL, and pass it as `--client-metadata-url`.

## Claude Code, Claude Desktop, Claude.ai, Cowork

Anthropic documents CIMD for Claude Code. An independent capture on 15 May 2026 ([Leduccc](https://leduccc.medium.com/testing-cimd-support-across-anthropics-claude-products-585366dbe089)) saw all four surfaces send CIMD `client_id` URLs when the server advertised `client_id_metadata_document_supported: true` and `token_endpoint_auth_methods_supported` including `"none"`. This server advertises both. I did not repeat that capture in October 2026.

One known gap. Claude Code's published metadata lists `http://localhost/callback` and `http://127.0.0.1/callback` with no port, then redirects at runtime to an OS-assigned loopback port. This server matches `redirect_uri` exactly, as MCP and RFC 9700 require. RFC 8252 §7.3 says native-app servers should accept any port on loopback. The two specs overlap here, and this server sides with exact match, so Claude Code's default document is rejected. That is a deliberate choice, not a bug to hide.

Web, Desktop, and Cowork need a public HTTPS MCP URL because Anthropic's servers fetch your metadata and call `/mcp`. Local `wrangler dev` is not enough.

## Cursor, Windsurf, VS Code

The same May 2026 write-up saw Cursor and Windsurf pick DCR when both were offered. With `ENABLE_DEPRECATED_DCR` off they fail OAuth unless they have added CIMD since. Set the flag to `true` only to test the old path.
