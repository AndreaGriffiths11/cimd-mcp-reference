# Security notes

What this server does to stay safe, and where the limits are.

## Transport

Production traffic is HTTPS. Wrangler's local HTTP is for development only.

## Tokens

- Access tokens are bound to `{issuer}/mcp`. A token minted for any other resource gets a 401 at `/mcp`.
- Tokens are opaque and stored as SHA-256 hashes, so a storage leak does not leak usable tokens.
- Authorization codes are single-use and consumed atomically inside the Durable Object.
- Refresh tokens rotate. Replaying an old one revokes the whole grant, which turns a stolen refresh token into a detectable event.
- Replacement tokens require an existing, unexpired grant. A refresh request already in flight cannot recreate a grant after replay revokes it.

## Metadata fetches (SSRF)

The server fetches a URL the client chose. That is the main attack surface of CIMD.

- IP literals and non-public hostnames are refused before any network call.
- DNS is resolved over HTTPS and every A/AAAA answer is checked against RFC 6890 special-use ranges (private, loopback, link-local, cloud metadata, documentation, and the rest of that registry).
- Redirects are never followed. Size is capped at 5 KiB, time at 5 seconds, content type must be JSON.
- The Worker's outbound fetch leaves from Cloudflare's network, which has no route into the private network of whoever deploys the Worker.

`CIMD_ALLOWED_HOSTS` turns the open model into an allow list if you want one.

## Form bodies

`POST /token`, `POST /revoke`, and `POST /authorize/decision` accept at most 16 KiB of form data. A larger `Content-Length` is refused before the body is read. Without `Content-Length`, the body is counted while it streams in and reading stops at the limit.

## Known limitations

### DNS rebinding in the metadata fetch

The SSRF check resolves the `client_id` host with DNS over HTTPS, then `fetch()` resolves it again. Workers cannot tell `fetch()` to connect to the address that was checked. An attacker who controls DNS for a `client_id` host can answer with a public address for the check and a different one for the fetch. The check narrows this window. It does not close it.

What limits the impact on this server:

- Outside local development, `client_id` must be `https`. The target has to present a valid certificate for the attacker's hostname, which internal services normally cannot.
- The fetch leaves from Cloudflare's network, which has no route into your private network.
- Redirects are rejected, the fetch times out after 5 seconds, the body is capped at 5 KiB, and it must be a JSON document that passes validation.
- `CIMD_ALLOWED_HOSTS` limits fetches to hosts you list.

If you port this to a runtime that controls sockets (Node, Go, and so on), resolve once, check every address, and connect to the checked address while keeping the original hostname for TLS SNI and the `Host` header. Add egress network policy that blocks private ranges as well.

## Consent screen

The consent screen is the trust UI. It shows the `client_id` host and the redirect host so a person can see who is asking and where the code will go. Loopback redirects get an extra warning because CIMD cannot prove which local process will receive the code. `logo_uri` is not rendered, so a client cannot dress up as another.

## Identity

There is one demo resource owner, `demo-user`. All authorized clients share that user's notes. The hosted demo intentionally has no consent password and accepts anyone who approves the consent screen. Store only public-safe demo data.

For your own deployment, set `CONSENT_PASSWORD` if you want to restrict consent, but do not treat it as per-user isolation. This is a reference for the client-identity side of OAuth, not an identity provider.

## Secrets

Copy `.dev.vars.example` to `.dev.vars` for loopback development. `.dev.vars`, its environment-specific variants, and `.env` files are ignored by Git. Keep real credentials out of example files. Production secrets go through `wrangler secret put`.

Before making a repository public, review retained branches, pull-request refs, workflow logs and artifacts, and commit email addresses as well as the current files. Replacing a branch's history does not erase old GitHub objects. If a credential was ever exposed, revoke or rotate it rather than relying on a history rewrite. Enable GitHub secret scanning and push protection where available.
