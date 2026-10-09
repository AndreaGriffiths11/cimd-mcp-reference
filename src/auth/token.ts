import { type Config, type Env, LIFETIMES } from "../env.js";
import { FormError, json, NO_STORE, nowSeconds, oauthError, randomToken, readForm, sha256Base64url } from "../http.js";
import { type AccessTokenRecord, authStore } from "../store/auth-store.js";
import { verifyCodeVerifier } from "./pkce.js";
import { checkRequestedResource } from "./resource.js";

/**
 * POST /token
 *
 * Public clients only (`token_endpoint_auth_methods_supported: ["none"]`), so
 * the client is identified by `client_id` and proven by PKCE. Tokens are
 * opaque random strings; the resource server looks them up by hash in the
 * same Durable Object, which keeps this reference free of signing keys.
 */
export async function handleToken(request: Request, env: Env, config: Config): Promise<Response> {
  let form: URLSearchParams;
  try {
    form = await readForm(request);
  } catch (error) {
    if (error instanceof FormError) return oauthError("invalid_request", error.message);
    throw error;
  }
  if (request.headers.has("Authorization")) {
    return oauthError("invalid_client", "this server only supports public clients (token_endpoint_auth_method none)", 401);
  }
  const grantType = form.get("grant_type");
  switch (grantType) {
    case "authorization_code":
      return authorizationCodeGrant(form, env, config);
    case "refresh_token":
      return refreshTokenGrant(form, env, config);
    default:
      return oauthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
  }
}

async function authorizationCodeGrant(form: URLSearchParams, env: Env, config: Config): Promise<Response> {
  const code = form.get("code");
  const clientId = form.get("client_id");
  if (!code) return oauthError("invalid_request", "code is required");
  if (!clientId) return oauthError("invalid_request", "client_id is required");

  const store = authStore(env);
  const record = await store.consumeAuthorizationCode(await sha256Base64url(code));
  if (!record) return oauthError("invalid_grant", "authorization code is invalid, expired, or already used");

  if (record.clientId !== clientId) {
    return oauthError("invalid_grant", "authorization code was issued to a different client");
  }
  // OAuth 2.1 section 4.1.3: redirect_uri is required at the token endpoint when
  // it was included in the authorization request, which this server always requires.
  if (form.get("redirect_uri") !== record.redirectUri) {
    return oauthError("invalid_grant", "redirect_uri does not match the authorization request");
  }
  const pkce = await verifyCodeVerifier(form.get("code_verifier"), record.codeChallenge);
  if (!pkce.ok) return oauthError("invalid_grant", pkce.error);

  const resource = checkRequestedResource(form.get("resource"), config.resource);
  if (!resource.ok) return oauthError("invalid_target", resource.error);
  if (resource.resource !== record.resource) {
    return oauthError("invalid_target", "resource does not match the authorization request");
  }

  return issue(
    store,
    {
      clientId: record.clientId,
      scope: record.scope,
      resource: record.resource,
      subject: record.subject,
      grantId: record.grantId,
    },
    "authorization_code",
  );
}

async function refreshTokenGrant(form: URLSearchParams, env: Env, config: Config): Promise<Response> {
  const refreshToken = form.get("refresh_token");
  const clientId = form.get("client_id");
  if (!refreshToken) return oauthError("invalid_request", "refresh_token is required");
  if (!clientId) return oauthError("invalid_request", "client_id is required");

  const store = authStore(env);
  const rotated = await store.rotateRefreshToken(await sha256Base64url(refreshToken));
  if (!rotated.ok) {
    const why =
      rotated.reason === "reused"
        ? "refresh token was already used; the whole grant has been revoked"
        : rotated.reason === "expired"
          ? "refresh token has expired"
          : "refresh token is invalid";
    return oauthError("invalid_grant", why);
  }
  if (rotated.record.clientId !== clientId) {
    await store.revokeGrant(rotated.record.grantId);
    return oauthError("invalid_grant", "refresh token was issued to a different client");
  }
  // RFC 8707: resource on refresh is optional, but if present it must still be ours.
  const requested = form.get("resource");
  if (requested !== null) {
    const resource = checkRequestedResource(requested, config.resource);
    if (!resource.ok) return oauthError("invalid_target", resource.error);
  }
  // Scope may only be narrowed on refresh (RFC 6749 section 6).
  const requestedScope = form.get("scope");
  let scope = rotated.record.scope;
  if (requestedScope !== null) {
    const granted = new Set(scope.split(" "));
    const wanted = requestedScope.split(/\s+/).filter(Boolean);
    if (wanted.some((s) => !granted.has(s))) return oauthError("invalid_scope", "refresh cannot add scopes");
    scope = wanted.join(" ");
  }
  return issue(store, { ...rotated.record, scope }, "refresh_token");
}

async function issue(
  store: ReturnType<typeof authStore>,
  grant: Omit<AccessTokenRecord, "expiresAt">,
  grantType: "authorization_code" | "refresh_token",
): Promise<Response> {
  const accessToken = randomToken(32);
  const refreshToken = randomToken(32);
  const now = nowSeconds();
  const issued = await store.issueTokens(
    await sha256Base64url(accessToken),
    { ...grant, expiresAt: now + LIFETIMES.accessToken },
    await sha256Base64url(refreshToken),
    { ...grant, expiresAt: now + LIFETIMES.refreshToken },
    grantType,
  );
  if (!issued) return oauthError("invalid_grant", "grant has been revoked or has expired");
  return json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: LIFETIMES.accessToken,
      refresh_token: refreshToken,
      scope: grant.scope,
    },
    { status: 200 },
    NO_STORE,
  );
}

/** POST /revoke (RFC 7009). Always answers 200 for well-formed requests. */
export async function handleRevoke(request: Request, env: Env): Promise<Response> {
  let form: URLSearchParams;
  try {
    form = await readForm(request);
  } catch (error) {
    if (error instanceof FormError) return oauthError("invalid_request", error.message);
    throw error;
  }
  const token = form.get("token");
  if (!token) return oauthError("invalid_request", "token is required");
  await authStore(env).revokeToken(await sha256Base64url(token));
  return new Response(null, { status: 200, headers: NO_STORE });
}
