/**
 * End-to-end tests against the Worker itself (via the SELF service binding).
 * Outbound fetches are answered by the fake internet in vitest.config.ts.
 */
import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { computeCodeChallenge } from "../src/auth/pkce.js";
import { sha256Base64url } from "../src/http.js";
import type { AuthStore } from "../src/store/auth-store.js";

const ISSUER = "http://localhost:8787";
const RESOURCE = `${ISSUER}/mcp`;
const CLIENT_ID = "https://good-client.example.com/client.json";
const REDIRECT_URI = "http://127.0.0.1:3000/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
let CHALLENGE: string;

beforeAll(async () => {
  CHALLENGE = await computeCodeChallenge(VERIFIER);
});

function authorizeUrl(overrides: Record<string, string | null> = {}): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    scope: "mcp:tools",
    resource: RESOURCE,
  });
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) params.delete(k);
    else params.set(k, v);
  }
  return `${ISSUER}/authorize?${params}`;
}

async function approveConsent(page: Response, alreadyReadBody?: string): Promise<URL> {
  expect(page.status).toBe(200);
  const body = alreadyReadBody ?? (await page.text());
  const requestId = /name="request_id" value="([^"]+)"/.exec(body)?.[1];
  expect(requestId).toBeTruthy();
  const decision = await SELF.fetch(`${ISSUER}/authorize/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: requestId!, decision: "approve" }),
    redirect: "manual",
  });
  expect(decision.status).toBe(302);
  return new URL(decision.headers.get("Location")!);
}

async function token(fields: Record<string, string>): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await SELF.fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function fullFlow(clientId = CLIENT_ID, redirectUri = REDIRECT_URI) {
  const page = await SELF.fetch(authorizeUrl({ client_id: clientId, redirect_uri: redirectUri }));
  const callback = await approveConsent(page);
  const code = callback.searchParams.get("code")!;
  const result = await token({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: VERIFIER,
    resource: RESOURCE,
  });
  expect(result.status).toBe(200);
  return result.body as { access_token: string; refresh_token: string; expires_in: number; scope: string; token_type: string };
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

/** Modern (2026-07-28) MCP request over Streamable HTTP, accepting JSON or SSE replies. */
async function mcp(method: string, params: Record<string, unknown>, accessToken?: string, headers: Record<string, string> = {}) {
  const meta = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": { name: "flow-test", version: "0.0.0" },
    "io.modelcontextprotocol/clientCapabilities": {},
  };
  const name = typeof params.name === "string" ? { "Mcp-Name": params.name } : {};
  const response = await SELF.fetch(RESOURCE, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": "2026-07-28",
      "Mcp-Method": method,
      ...name,
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: { ...params, _meta: meta } }),
  });
  let message: JsonRpcResponse | undefined;
  const contentType = response.headers.get("Content-Type") ?? "";
  if (response.status === 200) {
    const text = await response.text();
    if (contentType.startsWith("text/event-stream")) {
      const data = text
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trim());
      message = JSON.parse(data[data.length - 1]!) as JsonRpcResponse;
    } else {
      message = JSON.parse(text) as JsonRpcResponse;
    }
  }
  return { response, message };
}

describe("discovery", () => {
  it("serves protected resource metadata at the path-aware and root locations", async () => {
    for (const path of ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]) {
      const response = await SELF.fetch(`${ISSUER}${path}`);
      expect(response.status).toBe(200);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
      const prm = (await response.json()) as Record<string, unknown>;
      expect(prm.resource).toBe(RESOURCE);
      expect(prm.authorization_servers).toEqual([ISSUER]);
      expect(prm.scopes_supported).toEqual(["mcp:tools"]);
      expect(prm.bearer_methods_supported).toEqual(["header"]);
    }
  });

  it("serves authorization server metadata that advertises CIMD, PKCE S256, iss, and no DCR", async () => {
    const response = await SELF.fetch(`${ISSUER}/.well-known/oauth-authorization-server`);
    expect(response.status).toBe(200);
    const as = (await response.json()) as Record<string, unknown>;
    expect(as.issuer).toBe(ISSUER);
    expect(as.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(as.token_endpoint).toBe(`${ISSUER}/token`);
    expect(as.client_id_metadata_document_supported).toBe(true);
    expect(as.code_challenge_methods_supported).toEqual(["S256"]);
    expect(as.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(as.authorization_response_iss_parameter_supported).toBe(true);
    expect(as.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(as).not.toHaveProperty("registration_endpoint");
  });

  it("answers an unauthenticated MCP request with a 401 challenge pointing at the resource metadata", async () => {
    const { response } = await mcp("tools/list", {});
    expect(response.status).toBe(401);
    const challenge = response.headers.get("WWW-Authenticate") ?? "";
    expect(challenge).toMatch(/^Bearer /);
    expect(challenge).toContain(`resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp"`);
    expect(challenge).toContain('scope="mcp:tools"');
  });

  it("serves sample Inspector Client ID Metadata Documents whose client_id equals the document URL", async () => {
    const response = await SELF.fetch(`${ISSUER}/examples/inspector-web.json`);
    expect(response.status).toBe(200);
    const doc = (await response.json()) as { client_id: string; redirect_uris: string[] };
    expect(doc.client_id).toBe(`${ISSUER}/examples/inspector-web.json`);
    expect(doc.redirect_uris).toEqual(["http://localhost:6274/oauth/callback"]);
  });

  it("answers OPTIONS preflight on public endpoints", async () => {
    const response = await SELF.fetch(`${ISSUER}/token`, { method: "OPTIONS", headers: { Origin: "https://x.example" } });
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Methods")).toContain("POST");
  });
});

describe("authorization with a Client ID Metadata Document", () => {
  it("fetches the document, shows the client identity on the consent screen, then redirects with code, state, and iss", async () => {
    const page = await SELF.fetch(authorizeUrl());
    expect(page.status).toBe(200);
    expect(page.headers.get("X-Frame-Options")).toBe("DENY");
    const body = await page.text();
    expect(body).toContain("Integration Test Client");
    expect(body).toContain("good-client.example.com");
    expect(body).toContain("127.0.0.1:3000");
    expect(body).toContain("runs on your own computer"); // loopback redirect warning
    expect(body).toContain("mcp:tools");

    const callback = await approveConsent(page, body);
    expect(callback.origin + callback.pathname).toBe(REDIRECT_URI);
    expect(callback.searchParams.get("state")).toBe("xyz");
    expect(callback.searchParams.get("iss")).toBe(ISSUER);
    expect(callback.searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("accepts a loopback http client_id in development mode", async () => {
    const localClientId = "http://127.0.0.1:8976/client-metadata.json";
    const page = await SELF.fetch(authorizeUrl({ client_id: localClientId, redirect_uri: "http://127.0.0.1:8976/callback" }));
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("Loopback Dev Client");
  });

  it("denies the request back to the client", async () => {
    const page = await SELF.fetch(authorizeUrl());
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())![1]!;
    const decision = await SELF.fetch(`${ISSUER}/authorize/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ request_id: requestId, decision: "deny" }),
      redirect: "manual",
    });
    const location = new URL(decision.headers.get("Location")!);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("xyz");
    expect(location.searchParams.get("iss")).toBe(ISSUER);
  });

  it("a consent form can only be submitted once", async () => {
    const page = await SELF.fetch(authorizeUrl());
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())![1]!;
    const submit = () =>
      SELF.fetch(`${ISSUER}/authorize/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ request_id: requestId, decision: "approve" }),
        redirect: "manual",
      });
    expect((await submit()).status).toBe(302);
    expect((await submit()).status).toBe(410);
  });

  describe("refuses before redirecting when the client cannot be trusted", () => {
    it("redirect_uri not in the document", async () => {
      const response = await SELF.fetch(authorizeUrl({ redirect_uri: "http://127.0.0.1:3001/callback" }), { redirect: "manual" });
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("redirect_uri is not registered");
    });

    it("document client_id does not match its URL", async () => {
      const response = await SELF.fetch(authorizeUrl({ client_id: "https://mismatch-client.example.com/client.json" }), { redirect: "manual" });
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("does not match the document URL");
    });

    it("document URL redirects", async () => {
      const response = await SELF.fetch(authorizeUrl({ client_id: "https://redirecting-client.example.com/client.json" }), { redirect: "manual" });
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("redirects are not followed");
    });

    it("host resolves to a private address (SSRF)", async () => {
      const response = await SELF.fetch(authorizeUrl({ client_id: "https://private-client.example.com/client.json" }), { redirect: "manual" });
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("private or special-use");
    });

    it("http client_id for a non-loopback host", async () => {
      const response = await SELF.fetch(authorizeUrl({ client_id: "http://good-client.example.com/client.json" }), { redirect: "manual" });
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("https");
    });

    it("opaque client_id when DCR is disabled", async () => {
      const response = await SELF.fetch(authorizeUrl({ client_id: "dcr_abc" }), { redirect: "manual" });
      expect(response.status).toBe(400);
      expect(await response.text()).toContain("Client ID Metadata Document");
    });
  });

  describe("redirects errors to a verified client", () => {
    async function expectRedirectError(overrides: Record<string, string | null>, error: string) {
      const response = await SELF.fetch(authorizeUrl(overrides), { redirect: "manual" });
      expect(response.status).toBe(302);
      const location = new URL(response.headers.get("Location")!);
      expect(location.origin + location.pathname).toBe(REDIRECT_URI);
      expect(location.searchParams.get("error")).toBe(error);
      expect(location.searchParams.get("state")).toBe("xyz");
      expect(location.searchParams.get("iss")).toBe(ISSUER);
      return location;
    }

    it("missing PKCE", () => expectRedirectError({ code_challenge: null }, "invalid_request"));
    it("plain PKCE method", () => expectRedirectError({ code_challenge_method: "plain" }, "invalid_request"));
    it("missing resource", () => expectRedirectError({ resource: null }, "invalid_target"));
    it("resource for another server", () => expectRedirectError({ resource: "https://other.example.com/mcp" }, "invalid_target"));
    it("unknown scope", () => expectRedirectError({ scope: "admin" }, "invalid_scope"));
    it("unsupported response_type", () => expectRedirectError({ response_type: "token" }, "unsupported_response_type"));
  });
});

describe("token endpoint", () => {
  it("exchanges a code with a valid PKCE verifier and resource for audience-bound tokens", async () => {
    const tokens = await fullFlow();
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.scope).toBe("mcp:tools");
    expect(tokens.expires_in).toBe(3600);
    expect(tokens.refresh_token).toBeTruthy();

    const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global")) as DurableObjectStub<AuthStore>;
    const record = await stub.getAccessToken(await sha256Base64url(tokens.access_token));
    expect(record?.resource).toBe(RESOURCE);
    expect(record?.clientId).toBe(CLIENT_ID);
  });

  it("rejects a wrong code_verifier, and the code is burned on first use", async () => {
    const page = await SELF.fetch(authorizeUrl());
    const code = (await approveConsent(page)).searchParams.get("code")!;
    const wrong = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-wrong",
      resource: RESOURCE,
    });
    expect(wrong.status).toBe(400);
    expect(wrong.body.error).toBe("invalid_grant");

    const retry = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: VERIFIER,
      resource: RESOURCE,
    });
    expect(retry.status).toBe(400);
    expect(retry.body.error).toBe("invalid_grant");
  });

  it("rejects a code presented by a different client_id or redirect_uri", async () => {
    const page = await SELF.fetch(authorizeUrl());
    const code = (await approveConsent(page)).searchParams.get("code")!;
    const other = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: "https://mismatch-client.example.com/client.json",
      code_verifier: VERIFIER,
      resource: RESOURCE,
    });
    expect(other.body.error).toBe("invalid_grant");
  });

  it("rejects a token request for a different resource than authorized", async () => {
    const page = await SELF.fetch(authorizeUrl());
    const code = (await approveConsent(page)).searchParams.get("code")!;
    const result = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: VERIFIER,
      resource: "https://other.example.com/mcp",
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_target");
  });

  it("rotates refresh tokens and revokes the grant when an old one is replayed", async () => {
    const first = await fullFlow();
    const second = await token({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: CLIENT_ID });
    expect(second.status).toBe(200);
    expect(second.body.refresh_token).not.toBe(first.refresh_token);

    const replay = await token({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: CLIENT_ID });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");

    // The replay revoked everything issued under that grant, including the newest access token.
    const { response } = await mcp("tools/list", {}, second.body.access_token as string);
    expect(response.status).toBe(401);
  });

  it("revokes tokens (RFC 7009)", async () => {
    const tokens = await fullFlow();
    const revoke = await SELF.fetch(`${ISSUER}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: tokens.access_token }),
    });
    expect(revoke.status).toBe(200);
    const { response } = await mcp("tools/list", {}, tokens.access_token);
    expect(response.status).toBe(401);
  });

  it("refuses client authentication and unknown grant types", async () => {
    const response = await SELF.fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic abc" },
      body: new URLSearchParams({ grant_type: "authorization_code" }),
    });
    expect(response.status).toBe(401);
    expect((await token({ grant_type: "client_credentials" })).body.error).toBe("unsupported_grant_type");
  });
});

describe("MCP endpoint", () => {
  it("serves tools to a valid token and reports the token's audience through whoami", async () => {
    const tokens = await fullFlow();
    const list = await mcp("tools/list", {}, tokens.access_token);
    expect(list.response.status).toBe(200);
    const tools = (list.message?.result?.tools as Array<{ name: string }>).map((t) => t.name);
    expect(tools).toEqual(["whoami", "current_time", "add_note", "list_notes"]);

    const call = await mcp("tools/call", { name: "whoami", arguments: {} }, tokens.access_token);
    expect(call.response.status).toBe(200);
    const structured = call.message?.result?.structuredContent as Record<string, unknown>;
    expect(structured.client_id).toBe(CLIENT_ID);
    expect(structured.client_registration).toBe("client-id-metadata-document");
    expect(structured.audience).toBe(RESOURCE);
    expect(structured.scopes).toEqual(["mcp:tools"]);
  });

  it("refuses a token whose audience is a different resource", async () => {
    const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global")) as DurableObjectStub<AuthStore>;
    const foreign = "token-for-another-server";
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    await stub.issueTokens(
      await sha256Base64url(foreign),
      { clientId: CLIENT_ID, scope: "mcp:tools", resource: "https://other.example.com/mcp", subject: "demo-user", grantId: "g1", expiresAt },
      undefined,
      undefined,
    );
    const { response } = await mcp("tools/list", {}, foreign);
    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
  });

  it("refuses a token missing the required scope with 403 insufficient_scope", async () => {
    const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global")) as DurableObjectStub<AuthStore>;
    const scoped = "token-with-no-scope";
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    await stub.issueTokens(
      await sha256Base64url(scoped),
      { clientId: CLIENT_ID, scope: "", resource: RESOURCE, subject: "demo-user", grantId: "g2", expiresAt },
      undefined,
      undefined,
    );
    const { response } = await mcp("tools/list", {}, scoped);
    expect(response.status).toBe(403);
    expect(response.headers.get("WWW-Authenticate")).toContain('error="insufficient_scope"');
  });

  it("refuses expired and garbage tokens", async () => {
    const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global")) as DurableObjectStub<AuthStore>;
    const expired = "expired-token";
    await stub.issueTokens(
      await sha256Base64url(expired),
      { clientId: CLIENT_ID, scope: "mcp:tools", resource: RESOURCE, subject: "demo-user", grantId: "g3", expiresAt: Math.floor(Date.now() / 1000) - 1 },
      undefined,
      undefined,
    );
    expect((await mcp("tools/list", {}, expired)).response.status).toBe(401);
    expect((await mcp("tools/list", {}, "nonsense")).response.status).toBe(401);
  });

  it("validates the Origin header", async () => {
    const tokens = await fullFlow();
    const blocked = await mcp("tools/list", {}, tokens.access_token, { Origin: "https://evil.example.com" });
    expect(blocked.response.status).toBe(403);
    const allowed = await mcp("tools/list", {}, tokens.access_token, { Origin: "https://allowed-app.example.com" });
    expect(allowed.response.status).toBe(200);
    expect(allowed.response.headers.get("Access-Control-Allow-Origin")).toBe("https://allowed-app.example.com");
  });
});

describe("deprecated dynamic client registration", () => {
  it("is disabled by default", async () => {
    const response = await SELF.fetch(`${ISSUER}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI] }),
    });
    expect(response.status).toBe(404);
  });
});
