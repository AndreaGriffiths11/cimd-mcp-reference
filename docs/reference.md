# Reference

Endpoints, behaviour, and configuration. Read the [README](../README.md) first.

## Endpoints

| Path | Purpose |
| --- | --- |
| `GET /.well-known/oauth-protected-resource/mcp` | RFC 9728 resource metadata (also served at `/.well-known/oauth-protected-resource`) |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 server metadata |
| `GET /authorize` | Fetches the CIMD document, shows consent |
| `POST /authorize/decision` | Consent form target, redirects with `code` and `iss` |
| `POST /token` | `authorization_code` and `refresh_token` grants |
| `POST /revoke` | RFC 7009 |
| `POST /register` | RFC 7591 DCR, only when `ENABLE_DEPRECATED_DCR=true` |
| `POST /mcp` | Streamable HTTP MCP endpoint, Bearer token required |
| `GET /examples/inspector-web.json` | CIMD document for MCP Inspector web (`http://localhost:6274/oauth/callback`) |
| `GET /examples/inspector-cli.json` | CIMD document for Inspector CLI/TUI (`http://127.0.0.1:6276/oauth/callback`) |

Unauthenticated `/mcp` requests get:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="{issuer}/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"
```

Server metadata includes `client_id_metadata_document_supported: true`, `code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported: ["none"]`, and `authorization_response_iss_parameter_supported: true`.

## CIMD rules

The `client_id` URL must:

- use `https` (or loopback `http` when `DEV_ALLOW_LOOPBACK_CLIENT_IDS=true` and the issuer is also loopback),
- have a path, no fragment, no userinfo, no `.` or `..` segments,
- not be an IP literal or a non-public hostname,
- not be on a host whose DNS answers include any RFC 6890 special-use address.

The document must:

- return HTTP 200 with `application/json` or `application/*+json`,
- be at most 5 KiB, arrive within 5 seconds, with no redirects followed,
- contain `client_id` equal to the URL (string comparison),
- contain `redirect_uris`; the request `redirect_uri` must match one entry exactly.

Documents are cached in the Durable Object, bounded by count and age. `logo_uri` is never rendered.

## Tokens

- Authorization code + PKCE S256 only. `plain` is refused.
- `resource` (RFC 8707) is required and must equal `{issuer}/mcp`.
- Access tokens are opaque random strings stored as SHA-256 hashes. Audience is checked on every `/mcp` call.
- Refresh tokens rotate on each use. Replaying an old one revokes the whole grant.
- Every authorization redirect carries `iss` (RFC 9207).

## MCP tools

| Tool | Does |
| --- | --- |
| `whoami` | Returns subject, scopes, and `client_registration` (`client-id-metadata-document` or `dynamic-client-registration`) |
| `current_time` | ISO 8601 timestamp |
| `add_note` | Stores a note for the token's subject |
| `list_notes` | Lists that subject's notes |

Protocol revision 2026-07-28. Older `initialize` clients are served statelessly.

## Configuration

Set in `wrangler.jsonc` (`vars`), `.dev.vars` (local), or `wrangler secret put`.

| Name | Default | Meaning |
| --- | --- | --- |
| `ISSUER` | empty | Public HTTPS origin. Empty derives it from each request, which is fine for `wrangler dev` |
| `DEV_ALLOW_LOOPBACK_CLIENT_IDS` | `false` | Accept `http://127.0.0.1` CIMD URLs. Only honoured when the issuer is loopback too |
| `ENABLE_DEPRECATED_DCR` | `false` | Expose `POST /register` and `registration_endpoint` |
| `CIMD_ALLOWED_HOSTS` | empty | Comma-separated allow list of metadata hosts. Empty means any public host |
| `ALLOWED_ORIGINS` | empty | Browser origins allowed to call `/mcp` |
| `CONSENT_PASSWORD` | unset | Secret. When set, consent requires it before a code is issued |

## Deprecated DCR

Off by default. When on, `POST /register` returns `201` with a `Deprecation: true` header and a `deprecation_notice` field. Generated ids start with `dcr_`, never `https://`. Turn it on only to compare the old path.
