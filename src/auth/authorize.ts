import { type Config, type Env, LIFETIMES, SCOPES_SUPPORTED } from "../env.js";
import { FormError, html, nowSeconds, randomToken, readForm, sha256Base64url, timingSafeEqual } from "../http.js";
import { authStore } from "../store/auth-store.js";
import { CimdError, redirectUriIsRegistered } from "./cimd.js";
import { resolveClient } from "./clients.js";
import { renderConsent, renderError } from "./consent-page.js";
import { validateCodeChallenge } from "./pkce.js";
import { checkRequestedResource } from "./resource.js";

/** Identity of the resource owner. This reference server has one demo user; see README, Security notes. */
const DEMO_SUBJECT = "demo-user";

/**
 * GET /authorize
 *
 * Order matters for error handling (OAuth 2.1 section 4.1.2.1): until the
 * client and its redirect_uri are verified, errors are shown to the user and
 * never redirected. After that point errors go back to the client's
 * redirect_uri together with `state` and `iss`.
 */
export async function handleAuthorize(request: Request, env: Env, config: Config): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  if (!clientId) return errorPage("Missing client_id", "The authorization request did not include a client_id.");
  if (!redirectUri) return errorPage("Missing redirect_uri", "The authorization request did not include a redirect_uri.");

  let client;
  try {
    client = await resolveClient(clientId, config, env);
  } catch (error) {
    if (error instanceof CimdError) {
      return errorPage("Client could not be verified", error.message, { client_id: clientId }, error.code === "server_error" ? 502 : 400);
    }
    throw error;
  }

  if (!redirectUriIsRegistered(client.metadata, redirectUri)) {
    return errorPage("redirect_uri is not registered", "The redirect_uri does not exactly match any redirect_uris entry in the client's metadata document.", {
      client_id: clientId,
      redirect_uri: redirectUri,
      registered: client.metadata.redirect_uris.join("  "),
    });
  }

  // From here on the redirect target is trusted and errors go back to the client.
  const state = params.get("state") ?? undefined;
  const fail = (error: string, description: string) => redirectWithError(redirectUri, config, error, description, state);

  if (params.get("response_type") !== "code") return fail("unsupported_response_type", "response_type must be code");

  const pkce = validateCodeChallenge(params.get("code_challenge"), params.get("code_challenge_method"));
  if (!pkce.ok) return fail("invalid_request", pkce.error);

  const resource = checkRequestedResource(params.get("resource"), config.resource);
  if (!resource.ok) return fail("invalid_target", resource.error);

  const requestedScopes = (params.get("scope") ?? "").split(/\s+/).filter(Boolean);
  const unknown = requestedScopes.filter((s) => !(SCOPES_SUPPORTED as readonly string[]).includes(s));
  if (unknown.length) return fail("invalid_scope", `unknown scope: ${unknown.join(" ")}`);
  const scopes = requestedScopes.length ? requestedScopes : [...SCOPES_SUPPORTED];

  const requestId = randomToken(32);
  await authStore(env).savePendingAuthorization(requestId, {
    clientId,
    clientName: client.metadata.client_name,
    clientUri: client.metadata.client_uri,
    redirectUri,
    state,
    codeChallenge: params.get("code_challenge")!,
    scope: scopes.join(" "),
    resource: resource.resource,
    registration: client.registration,
    expiresAt: nowSeconds() + LIFETIMES.pendingAuthorization,
  });

  return html(
    renderConsent({
      requestId,
      clientId,
      clientName: client.metadata.client_name,
      clientUri: client.metadata.client_uri,
      redirectUri,
      scopes,
      resource: resource.resource,
      registration: client.registration,
      requirePassword: config.consentPassword !== undefined,
    }),
  );
}

/** POST /authorize/decision: the consent form. */
export async function handleDecision(request: Request, env: Env, config: Config): Promise<Response> {
  let form: URLSearchParams;
  try {
    form = await readForm(request);
  } catch (error) {
    if (error instanceof FormError) return errorPage(error.status === 413 ? "Request too large" : "Bad request", error.message, undefined, error.status);
    throw error;
  }
  const requestId = form.get("request_id") ?? "";
  if (!/^[A-Za-z0-9\-_]{43}$/.test(requestId)) return errorPage("Bad request", "Missing or malformed request_id.");

  const store = authStore(env);
  const pending = await store.takePendingAuthorization(requestId);
  if (!pending) {
    return errorPage("Request expired", "This consent screen is no longer valid. Start the authorization again from your MCP client.", undefined, 410);
  }

  if (config.consentPassword !== undefined) {
    const supplied = form.get("password") ?? "";
    if (!timingSafeEqual(supplied, config.consentPassword)) {
      // Re-arm the pending request so the user can retry once more.
      const retryId = randomToken(32);
      await store.savePendingAuthorization(retryId, pending);
      return html(
        renderConsent({
          requestId: retryId,
          clientId: pending.clientId,
          clientName: pending.clientName,
          clientUri: pending.clientUri,
          redirectUri: pending.redirectUri,
          scopes: pending.scope.split(" "),
          resource: pending.resource,
          registration: pending.registration,
          requirePassword: true,
          passwordError: true,
        }),
        { status: 401 },
      );
    }
  }

  if (form.get("decision") !== "approve") {
    return redirectWithError(pending.redirectUri, config, "access_denied", "The user denied the request", pending.state);
  }

  const code = randomToken(32);
  await store.saveAuthorizationCode(await sha256Base64url(code), {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    scope: pending.scope,
    resource: pending.resource,
    subject: DEMO_SUBJECT,
    grantId: randomToken(16),
    expiresAt: nowSeconds() + LIFETIMES.authorizationCode,
  });

  const location = new URL(pending.redirectUri);
  location.searchParams.set("code", code);
  if (pending.state !== undefined) location.searchParams.set("state", pending.state);
  location.searchParams.set("iss", config.issuer); // RFC 9207
  return redirect(location);
}

function redirectWithError(redirectUri: string, config: Config, error: string, description: string, state: string | undefined): Response {
  const location = new URL(redirectUri);
  location.searchParams.set("error", error);
  location.searchParams.set("error_description", description);
  if (state !== undefined) location.searchParams.set("state", state);
  location.searchParams.set("iss", config.issuer);
  return redirect(location);
}

function redirect(location: URL): Response {
  return new Response(null, {
    status: 302,
    headers: { Location: location.href, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" },
  });
}

function errorPage(title: string, description: string, details?: Record<string, string>, status = 400): Response {
  return html(renderError(title, description, details), { status });
}
