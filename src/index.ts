import { requireBearerAuth } from "@modelcontextprotocol/server";
import { handleAuthorize, handleDecision } from "./auth/authorize.js";
import { handleRegister } from "./auth/dcr.js";
import { buildExampleClientMetadata, INSPECTOR_CLI_PATH, INSPECTOR_WEB_PATH } from "./auth/example-clients.js";
import { authorizationServerMetadata, protectedResourceMetadata } from "./auth/metadata.js";
import { handleRevoke, handleToken } from "./auth/token.js";
import { type Config, type Env, isLoopbackHostname, MCP_PATH, REQUIRED_SCOPE, resolveConfig } from "./env.js";
import { escapeHtml, html, json, preflight, withCors } from "./http.js";
import { createMcpFetchHandler } from "./mcp/server.js";
import { tokenVerifier } from "./mcp/verify.js";

export { AuthStore } from "./store/auth-store.js";

let mcpHandler: ReturnType<typeof createMcpFetchHandler> | undefined;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const config = resolveConfig(env, request);
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // Public, unauthenticated documents and endpoints that browser-based clients may call cross-origin.
    const corsRoutes = new Set([
      "/.well-known/oauth-authorization-server",
      "/.well-known/oauth-protected-resource",
      `/.well-known/oauth-protected-resource${MCP_PATH}`,
      "/token",
      "/revoke",
      "/register",
      INSPECTOR_WEB_PATH,
      INSPECTOR_CLI_PATH,
    ]);
    if (request.method === "OPTIONS" && corsRoutes.has(path)) return preflight(request);

    const response = await route(request, env, config, path);
    return corsRoutes.has(path) ? withCors(response, request) : response;
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env, config: Config, path: string): Promise<Response> {
  switch (path) {
    case "/":
      return landingPage(config);

    // RFC 8414 (the authorization server is co-located with the resource server).
    case "/.well-known/oauth-authorization-server":
      return request.method === "GET" ? metadata(authorizationServerMetadata(config)) : methodNotAllowed("GET");

    // RFC 9728, both the path-aware location MCP clients try first and the root location.
    case "/.well-known/oauth-protected-resource":
    case `/.well-known/oauth-protected-resource${MCP_PATH}`:
      return request.method === "GET" ? metadata(protectedResourceMetadata(config)) : methodNotAllowed("GET");

    case "/authorize":
      return request.method === "GET" ? handleAuthorize(request, env, config) : methodNotAllowed("GET");
    case "/authorize/decision":
      return request.method === "POST" ? handleDecision(request, env, config) : methodNotAllowed("POST");
    case "/token":
      return request.method === "POST" ? handleToken(request, env, config) : methodNotAllowed("POST");
    case "/revoke":
      return request.method === "POST" ? handleRevoke(request, env) : methodNotAllowed("POST");
    case "/register":
      return request.method === "POST" ? handleRegister(request, env, config) : methodNotAllowed("POST");

    case MCP_PATH:
      return handleMcp(request, env, config);

    // Sample Client ID Metadata Documents. The client_id is this request's
    // URL so a deployed copy and a local wrangler each produce a matching document.
    case INSPECTOR_WEB_PATH:
    case INSPECTOR_CLI_PATH:
      return request.method === "GET" ? exampleClientMetadata(request) : methodNotAllowed("GET");

    default:
      return json({ error: "not_found" }, { status: 404 });
  }
}

/**
 * The MCP endpoint: Origin check, bearer token gate, then the MCP handler.
 *
 * `requireBearerAuth` answers 401 with
 *   WWW-Authenticate: Bearer error="invalid_token", ..., scope="mcp:tools",
 *                     resource_metadata="<issuer>/.well-known/oauth-protected-resource/mcp"
 * which is the discovery entry point for MCP clients (RFC 9728 section 5.1).
 */
async function handleMcp(request: Request, env: Env, config: Config): Promise<Response> {
  const origin = request.headers.get("Origin");
  if (origin !== null && !originAllowed(origin, config)) {
    return json({ jsonrpc: "2.0", error: { code: -32000, message: "Origin not allowed" }, id: null }, { status: 403 });
  }

  const gate = requireBearerAuth({
    verifier: tokenVerifier(env, config),
    requiredScopes: [REQUIRED_SCOPE],
    resourceMetadataUrl: config.resourceMetadataUrl,
    expectedResource: new URL(config.resource),
  });
  const auth = await gate(request);
  if (auth instanceof Response) return corsForOrigin(auth, origin, config);

  mcpHandler ??= createMcpFetchHandler(env);
  const response = await mcpHandler.fetch(request, { authInfo: auth });
  return corsForOrigin(response, origin, config);
}

function originAllowed(origin: string, config: Config): boolean {
  if (config.allowedOrigins.includes(origin)) return true;
  try {
    const hostname = new URL(origin).hostname;
    return config.issuerIsLoopback && isLoopbackHostname(hostname);
  } catch {
    return false;
  }
}

function corsForOrigin(response: Response, origin: string | null, config: Config): Response {
  if (origin === null || !originAllowed(origin, config)) return response;
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Expose-Headers", "WWW-Authenticate, MCP-Protocol-Version");
  headers.set("Vary", "Origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function metadata(document: Record<string, unknown>): Response {
  return json(document, { status: 200 }, { "Cache-Control": "public, max-age=300" });
}

function exampleClientMetadata(request: Request): Response {
  const url = new URL(request.url);
  const clientId = `${url.origin}${url.pathname}`;
  const document = buildExampleClientMetadata(clientId);
  if (!document) return json({ error: "not_found" }, { status: 404 });
  return metadata(document);
}

function methodNotAllowed(allow: string): Response {
  return json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: allow } });
}

function landingPage(config: Config): Response {
  const link = (href: string) => `<li><a href="${escapeHtml(href)}"><code>${escapeHtml(href)}</code></a></li>`;
  return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CIMD MCP reference server</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}code{font-family:ui-monospace,monospace}</style></head>
<body><h1>CIMD MCP reference server</h1>
<p>A remote MCP server that accepts OAuth clients identified by a Client ID Metadata Document. Point an MCP client at <code>${escapeHtml(config.resource)}</code>.</p>
<ul>
${link(`${config.issuer}/.well-known/oauth-protected-resource${MCP_PATH}`)}
${link(`${config.issuer}/.well-known/oauth-authorization-server`)}
</ul>
<p>Source and documentation: <a href="https://github.com/AndreaGriffiths11/cimd-mcp-reference">github.com/AndreaGriffiths11/cimd-mcp-reference</a></p>
</body></html>`);
}
