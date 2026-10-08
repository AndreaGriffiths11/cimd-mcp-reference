import type { AuthStore } from "./store/auth-store.js";

/** Bindings and variables declared in wrangler.jsonc (plus optional secrets). */
export interface Env {
  AUTH_STORE: DurableObjectNamespace<AuthStore>;
  ISSUER?: string;
  DEV_ALLOW_LOOPBACK_CLIENT_IDS?: string;
  ENABLE_DEPRECATED_DCR?: string;
  ALLOWED_ORIGINS?: string;
  CIMD_ALLOWED_HOSTS?: string;
  /** Optional secret. When set, the consent screen asks for it. */
  CONSENT_PASSWORD?: string;
}

/** Scopes this server understands. The MCP endpoint requires `mcp:tools`. */
export const SCOPES_SUPPORTED = ["mcp:tools"] as const;
export const REQUIRED_SCOPE = "mcp:tools";

/** Path of the MCP endpoint. The canonical resource URI is `${issuer}${MCP_PATH}`. */
export const MCP_PATH = "/mcp";

/** Lifetimes, in seconds. */
export const LIFETIMES = {
  pendingAuthorization: 10 * 60,
  authorizationCode: 60,
  accessToken: 60 * 60,
  refreshToken: 30 * 24 * 60 * 60,
} as const;

/** Resolved, per-request configuration derived from the environment and the request URL. */
export interface Config {
  /** Authorization server issuer identifier, also the public base URL of this Worker. */
  issuer: string;
  /** Canonical RFC 8707 resource identifier of the MCP endpoint. */
  resource: string;
  /** URL of the RFC 9728 protected resource metadata document. */
  resourceMetadataUrl: string;
  /** True when the issuer is a loopback address (local development). */
  issuerIsLoopback: boolean;
  /** Accept http:// loopback client_id URLs. Only possible when issuerIsLoopback. */
  allowLoopbackClientIds: boolean;
  /** Serve the deprecated RFC 7591 registration endpoint. */
  deprecatedDcrEnabled: boolean;
  /** Browser origins allowed to call /mcp. */
  allowedOrigins: string[];
  /** Hostnames allowed as CIMD client_id hosts. Empty means any public host. */
  cimdAllowedHosts: string[];
  consentPassword: string | undefined;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function isLoopbackHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return LOOPBACK_HOSTS.has(h) || h.endsWith(".localhost") || h.startsWith("127.");
}

function flag(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "true";
}

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function resolveConfig(env: Env, request: Request): Config {
  const requestOrigin = new URL(request.url).origin;
  const issuer = (env.ISSUER?.trim() || requestOrigin).replace(/\/+$/, "");
  const issuerUrl = new URL(issuer);
  const issuerIsLoopback = isLoopbackHostname(issuerUrl.hostname);
  return {
    issuer,
    resource: `${issuer}${MCP_PATH}`,
    resourceMetadataUrl: `${issuer}/.well-known/oauth-protected-resource${MCP_PATH}`,
    issuerIsLoopback,
    allowLoopbackClientIds: issuerIsLoopback && flag(env.DEV_ALLOW_LOOPBACK_CLIENT_IDS),
    deprecatedDcrEnabled: flag(env.ENABLE_DEPRECATED_DCR),
    allowedOrigins: list(env.ALLOWED_ORIGINS),
    cimdAllowedHosts: list(env.CIMD_ALLOWED_HOSTS).map((h) => h.toLowerCase()),
    consentPassword: env.CONSENT_PASSWORD?.trim() || undefined,
  };
}
