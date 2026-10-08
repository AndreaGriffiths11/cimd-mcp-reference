/**
 * OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
 *
 * A client identifies itself with an HTTPS URL as `client_id`. The authorization
 * server fetches the JSON document at that URL and treats it as the client's
 * registration. This module owns every rule about which URLs are acceptable,
 * how the document is fetched, and what a valid document looks like. It takes
 * its network and clock dependencies as arguments so the rules can be tested
 * without a network.
 */

import { isLoopbackHostname } from "../env.js";
import { isIpLiteral, isLoopbackAddress, isPublicHostname, isSpecialUseAddress, type ResolveAddresses } from "./ssrf.js";

export const CIMD_LIMITS = {
  /** Draft section 6.6 recommends 5 kilobytes. */
  maxDocumentBytes: 5 * 1024,
  maxClientIdLength: 2048,
  fetchTimeoutMs: 5000,
  /** Cache bounds applied to Cache-Control max-age (draft section 4.4). */
  minCacheSeconds: 60,
  maxCacheSeconds: 24 * 60 * 60,
  defaultCacheSeconds: 5 * 60,
} as const;

export class CimdError extends Error {
  constructor(
    /** OAuth error code to report to the client. */
    public readonly code: "invalid_client" | "invalid_request" | "server_error",
    message: string,
  ) {
    super(message);
    this.name = "CimdError";
  }
}

export interface ClientIdPolicy {
  /** Accept http://localhost and http://127.0.0.1 client_id URLs (local development only). */
  allowLoopbackHttp: boolean;
  /** When non-empty, only these hostnames may host a client_id document. */
  allowedHosts: string[];
}

/** True when the string looks like a URL-formatted client identifier (CIMD) rather than an opaque id. */
export function looksLikeClientIdUrl(clientId: string): boolean {
  return /^https?:\/\//i.test(clientId);
}

/**
 * Draft section 3: https scheme, a path component, no dot segments, no fragment,
 * no userinfo. Query strings are allowed (SHOULD NOT) and ports are allowed.
 */
export function validateClientIdUrl(clientId: string, policy: ClientIdPolicy): URL {
  if (clientId.length > CIMD_LIMITS.maxClientIdLength) {
    throw new CimdError("invalid_client", "client_id URL is too long");
  }
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw new CimdError("invalid_client", "client_id is not a valid URL");
  }
  // Simple string comparison (RFC 3986 section 6.2.1) means the document must
  // declare exactly this string, so we also refuse inputs that the URL parser
  // would normalise (for example a missing path or uppercase scheme).
  if (url.href !== clientId) {
    throw new CimdError("invalid_client", "client_id must be a normalised absolute URL (did you omit the path?)");
  }
  const loopback = isLoopbackHostname(url.hostname);
  if (url.protocol !== "https:") {
    if (!(url.protocol === "http:" && loopback && policy.allowLoopbackHttp)) {
      throw new CimdError("invalid_client", "client_id must use the https scheme");
    }
  }
  if (url.pathname === "" || url.pathname === "/") {
    throw new CimdError("invalid_client", "client_id must contain a path component");
  }
  if (url.pathname.split("/").some((segment) => segment === "." || segment === "..")) {
    throw new CimdError("invalid_client", "client_id must not contain dot path segments");
  }
  if (url.hash !== "" || clientId.includes("#")) {
    throw new CimdError("invalid_client", "client_id must not contain a fragment");
  }
  if (url.username !== "" || url.password !== "") {
    throw new CimdError("invalid_client", "client_id must not contain a username or password");
  }
  const host = url.hostname.toLowerCase();
  if (policy.allowedHosts.length > 0) {
    if (!policy.allowedHosts.includes(host)) {
      throw new CimdError("invalid_client", `client_id host ${host} is not on this server's allow list`);
    }
  } else if (!(loopback && policy.allowLoopbackHttp)) {
    if (isIpLiteral(host)) throw new CimdError("invalid_client", "client_id must use a DNS name, not an IP address");
    if (!isPublicHostname(host)) throw new CimdError("invalid_client", "client_id host must be a public DNS name");
  }
  return url;
}

/** Fields this server reads from a Client ID Metadata Document. Other members are kept verbatim. */
export interface ClientMetadata {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  grant_types?: string[];
  response_types?: string[];
  token_endpoint_auth_method?: string;
  [key: string]: unknown;
}

/**
 * Validates document contents (draft section 4.1 plus the MCP client registration
 * requirements). `documentUrl` is the exact string used as client_id.
 */
export function validateClientMetadataDocument(value: unknown, documentUrl: string): ClientMetadata {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CimdError("invalid_client", "client metadata document must be a JSON object");
  }
  const doc = value as Record<string, unknown>;

  if (doc.client_id !== documentUrl) {
    throw new CimdError("invalid_client", "client_id in the metadata document does not match the document URL");
  }
  if (typeof doc.client_name !== "string" || doc.client_name.trim() === "") {
    throw new CimdError("invalid_client", "client metadata document must include client_name");
  }
  if (doc.client_name.length > 200) {
    throw new CimdError("invalid_client", "client_name is too long");
  }
  if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) {
    throw new CimdError("invalid_client", "client metadata document must include a non-empty redirect_uris array");
  }
  for (const uri of doc.redirect_uris) {
    if (typeof uri !== "string") throw new CimdError("invalid_client", "redirect_uris must contain strings");
    assertAcceptableRedirectUri(uri);
  }
  // No shared secret can exist for a self-declared client (draft section 4.1).
  if ("client_secret" in doc || "client_secret_expires_at" in doc) {
    throw new CimdError("invalid_client", "client metadata document must not contain client_secret");
  }
  const authMethod = doc.token_endpoint_auth_method ?? "none";
  if (authMethod !== "none") {
    const hint =
      authMethod === "private_key_jwt"
        ? "private_key_jwt is permitted by the draft but this reference server only supports public clients"
        : "shared-secret authentication methods are forbidden for Client ID Metadata Documents";
    throw new CimdError("invalid_client", `token_endpoint_auth_method must be "none" (${hint})`);
  }
  if (doc.grant_types !== undefined) {
    if (!Array.isArray(doc.grant_types) || !doc.grant_types.includes("authorization_code")) {
      throw new CimdError("invalid_client", "grant_types must include authorization_code");
    }
  }
  if (doc.response_types !== undefined) {
    if (!Array.isArray(doc.response_types) || !doc.response_types.includes("code")) {
      throw new CimdError("invalid_client", "response_types must include code");
    }
  }
  for (const field of ["client_uri", "logo_uri"] as const) {
    if (doc[field] !== undefined) {
      if (typeof doc[field] !== "string" || !isAbsoluteHttpsUrl(doc[field] as string)) {
        throw new CimdError("invalid_client", `${field} must be an absolute https URL`);
      }
    }
  }
  return doc as unknown as ClientMetadata;
}

/** MCP security considerations: redirect URIs MUST be either localhost or https. */
export function assertAcceptableRedirectUri(uri: string): void {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new CimdError("invalid_client", `redirect URI is not an absolute URL: ${uri}`);
  }
  if (url.hash !== "" || uri.includes("#")) throw new CimdError("invalid_client", "redirect URIs must not contain a fragment");
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && isLoopbackHostname(url.hostname)) return;
  throw new CimdError("invalid_client", `redirect URI must use https or a loopback http address: ${uri}`);
}

/** RFC 9700: the redirect_uri in a request must exactly match a registered one. */
export function redirectUriIsRegistered(metadata: Pick<ClientMetadata, "redirect_uris">, redirectUri: string): boolean {
  return metadata.redirect_uris.includes(redirectUri);
}

function isAbsoluteHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

export interface FetchClientMetadataDeps {
  fetch: typeof fetch;
  resolve: ResolveAddresses;
  cache: {
    get(url: string): Promise<{ document: unknown; expiresAt: number } | undefined>;
    put(url: string, document: ClientMetadata, expiresAt: number): Promise<void>;
  };
  now?: () => number;
  limits?: Partial<typeof CIMD_LIMITS>;
  /**
   * When this returns a document, it is validated with the same rules as a
   * fetched body and the network is not used. Used only for this Worker's own
   * example Inspector documents (a Worker cannot fetch its own workers.dev URL).
   */
  localDocument?: (url: URL) => unknown | undefined;
}

export interface FetchClientMetadataResult {
  metadata: ClientMetadata;
  fromCache: boolean;
}

/**
 * Fetches and validates the document for an already-validated client_id URL.
 * Redirects are not followed, the response must be 200 with a JSON content
 * type, and the body is capped at `maxDocumentBytes`. Valid documents are
 * cached within the configured bounds; errors are never cached.
 */
export async function fetchClientMetadata(
  clientIdUrl: URL,
  policy: ClientIdPolicy,
  deps: FetchClientMetadataDeps,
): Promise<FetchClientMetadataResult> {
  const limits = { ...CIMD_LIMITS, ...deps.limits };
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const clientId = clientIdUrl.href;

  const cached = await deps.cache.get(clientId);
  if (cached && cached.expiresAt > now()) {
    return { metadata: validateClientMetadataDocument(cached.document, clientId), fromCache: true };
  }

  const local = deps.localDocument?.(clientIdUrl);
  if (local !== undefined) {
    return { metadata: validateClientMetadataDocument(local, clientId), fromCache: false };
  }

  await assertResolvesToPublicAddress(clientIdUrl, policy, deps.resolve);

  let response: Response;
  try {
    response = await deps.fetch(clientId, {
      method: "GET",
      headers: { Accept: "application/json", "User-Agent": "cimd-mcp-reference/0.1 (+https://github.com/AndreaGriffiths11/cimd-mcp-reference)" },
      redirect: "manual",
      signal: AbortSignal.timeout(limits.fetchTimeoutMs),
    });
  } catch (error) {
    const reason = error instanceof Error && error.name === "TimeoutError" ? "timed out" : "failed";
    throw new CimdError("invalid_client", `fetching the client metadata document ${reason}`);
  }

  if (response.status >= 300 && response.status < 400) {
    throw new CimdError("invalid_client", "client metadata document URL redirected; redirects are not followed");
  }
  if (response.status !== 200) {
    throw new CimdError("invalid_client", `client metadata document returned HTTP ${response.status}`);
  }
  const contentType = (response.headers.get("Content-Type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (!(contentType === "application/json" || (contentType.startsWith("application/") && contentType.endsWith("+json")))) {
    throw new CimdError("invalid_client", `client metadata document must be served as application/json, got ${contentType || "no content type"}`);
  }
  const declaredLength = Number(response.headers.get("Content-Length") ?? "0");
  if (declaredLength > limits.maxDocumentBytes) {
    throw new CimdError("invalid_client", `client metadata document exceeds ${limits.maxDocumentBytes} bytes`);
  }
  const text = await readBodyWithLimit(response, limits.maxDocumentBytes);

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CimdError("invalid_client", "client metadata document is not valid JSON");
  }
  const metadata = validateClientMetadataDocument(parsed, clientId);

  const ttl = cacheLifetimeSeconds(response.headers.get("Cache-Control"), limits);
  if (ttl > 0) await deps.cache.put(clientId, metadata, now() + ttl);
  return { metadata, fromCache: false };
}

async function assertResolvesToPublicAddress(url: URL, policy: ClientIdPolicy, resolve: ResolveAddresses): Promise<void> {
  const host = url.hostname;
  if (isLoopbackHostname(host) && policy.allowLoopbackHttp) return; // explicit local development exception
  let addresses: string[];
  try {
    addresses = await resolve(host);
  } catch {
    throw new CimdError("server_error", "could not resolve the client_id host");
  }
  if (addresses.length === 0) throw new CimdError("invalid_client", "client_id host does not resolve");
  for (const address of addresses) {
    if (isLoopbackAddress(address) || isSpecialUseAddress(address)) {
      throw new CimdError("invalid_client", "client_id host resolves to a private or special-use address");
    }
  }
}

async function readBodyWithLimit(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new CimdError("invalid_client", `client metadata document exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

/** Draft section 4.4: respect Cache-Control within our own bounds. Returns 0 when caching is not allowed. */
export function cacheLifetimeSeconds(cacheControl: string | null, limits: typeof CIMD_LIMITS = CIMD_LIMITS): number {
  if (!cacheControl) return limits.defaultCacheSeconds;
  const directives = cacheControl.toLowerCase().split(",").map((d) => d.trim());
  if (directives.includes("no-store")) return 0;
  const maxAge = directives.find((d) => d.startsWith("max-age="));
  if (!maxAge) return limits.defaultCacheSeconds;
  const seconds = Number(maxAge.slice("max-age=".length));
  if (!Number.isFinite(seconds) || seconds <= 0) return 0;
  return Math.min(limits.maxCacheSeconds, Math.max(limits.minCacheSeconds, Math.floor(seconds)));
}
