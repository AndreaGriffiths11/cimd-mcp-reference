import { type Config, type Env } from "../env.js";
import { json, NO_STORE, nowSeconds, oauthError, randomToken } from "../http.js";
import { authStore } from "../store/auth-store.js";
import { assertAcceptableRedirectUri, CimdError } from "./cimd.js";

/**
 * POST /register: OAuth 2.0 Dynamic Client Registration (RFC 7591).
 *
 * DEPRECATED. MCP 2026-07-28 deprecates DCR as a registration mechanism in
 * favour of Client ID Metadata Documents (spec PR #2858). It remains in the
 * spec for backwards compatibility and is eligible for removal no earlier
 * than 2027-07-28. This handler exists so readers can compare the two paths
 * side by side; it is off unless ENABLE_DEPRECATED_DCR=true, in which case
 * the metadata document also advertises `registration_endpoint`.
 *
 * Differences from CIMD worth noticing:
 *   - the server must store registration state for every client that shows up,
 *   - the generated client_id is only meaningful at this server,
 *   - the user cannot verify the client's identity beyond a self-asserted name.
 */
const REGISTRATION_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

export async function handleRegister(request: Request, env: Env, config: Config): Promise<Response> {
  if (!config.deprecatedDcrEnabled) {
    return oauthError("invalid_request", "dynamic client registration is disabled; use a Client ID Metadata Document as client_id", 404);
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return oauthError("invalid_client_metadata", "request body must be JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return oauthError("invalid_client_metadata", "request body must be a JSON object");
  }
  // Drop anything secret-shaped before it is stored or echoed back.
  const { client_secret: _secret, client_secret_expires_at: _secretExpiry, ...metadata } = body as Record<string, unknown>;
  if (!Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length === 0) {
    return oauthError("invalid_redirect_uri", "redirect_uris is required");
  }
  try {
    for (const uri of metadata.redirect_uris) {
      if (typeof uri !== "string") throw new CimdError("invalid_client", "redirect_uris must contain strings");
      assertAcceptableRedirectUri(uri);
    }
  } catch (error) {
    if (error instanceof CimdError) return oauthError("invalid_redirect_uri", error.message);
    throw error;
  }
  if (metadata.token_endpoint_auth_method !== undefined && metadata.token_endpoint_auth_method !== "none") {
    return oauthError("invalid_client_metadata", "only public clients (token_endpoint_auth_method none) are supported");
  }

  // Never starts with https:// so it cannot be confused with a CIMD URL (draft section 6.9).
  const clientId = `dcr_${randomToken(24)}`;
  const issuedAt = nowSeconds();
  const stored: Record<string, unknown> = {
    ...metadata,
    client_id: clientId,
    client_name: typeof metadata.client_name === "string" && metadata.client_name ? metadata.client_name : "Unnamed client (DCR)",
    token_endpoint_auth_method: "none",
    grant_types: Array.isArray(metadata.grant_types) ? metadata.grant_types : ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
  await authStore(env).saveRegisteredClient({ clientId, metadataJson: JSON.stringify(stored), expiresAt: issuedAt + REGISTRATION_LIFETIME_SECONDS });

  return json(
    {
      ...stored,
      client_id_issued_at: issuedAt,
      client_secret_expires_at: 0,
      deprecation_notice:
        "Dynamic Client Registration is deprecated in MCP 2026-07-28. Prefer a Client ID Metadata Document: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration",
    },
    { status: 201, headers: { Deprecation: "true" } },
    NO_STORE,
  );
}
