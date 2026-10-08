# Security notes

What this server does to stay safe, and where the limits are.

## Transport

Production traffic is HTTPS. Wrangler's local HTTP is for development only.

## Tokens

- Access tokens are bound to `{issuer}/mcp`. A token minted for any other resource gets a 401 at `/mcp`.
- Tokens are opaque and stored as SHA-256 hashes, so a storage leak does not leak usable tokens.
- Authorization codes are single-use and consumed atomically inside the Durable Object.
- Refresh tokens rotate. Replaying an old one revokes the whole grant, which turns a stolen refresh token into a detectable event.

## Metadata fetches (SSRF)

The server fetches a URL the client chose. That is the main attack surface of CIMD.

- IP literals and non-public hostnames are refused before any network call.
- DNS is resolved over HTTPS and every A/AAAA answer is checked against RFC 6890 special-use ranges (private, loopback, link-local, cloud metadata, documentation, and the rest of that registry).
- Redirects are never followed. Size is capped at 5 KiB, time at 5 seconds, content type must be JSON.
- Cloudflare Workers also cannot open connections to private addresses, which is a second layer.
- Residual risk: DNS rebinding between the DoH check and the fetch, on runtimes that can connect to the resolved IP. Workers cannot, so it does not apply here.

`CIMD_ALLOWED_HOSTS` turns the open model into an allow list if you want one.

## Consent screen

The consent screen is the trust UI. It shows the `client_id` host and the redirect host so a person can see who is asking and where the code will go. Loopback redirects get an extra warning because CIMD cannot prove which local process will receive the code. `logo_uri` is not rendered, so a client cannot dress up as another.

## Identity

There is one demo resource owner, `demo-user`. Set `CONSENT_PASSWORD` if the Worker is reachable by anyone but you. This is a reference for the client-identity side of OAuth, not an identity provider.

## Secrets

The repo holds none. `.dev.vars` only enables loopback CIMD for `wrangler dev`. Production secrets go through `wrangler secret put`.
