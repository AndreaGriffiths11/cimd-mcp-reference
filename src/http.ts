/** Small HTTP helpers shared by the authorization server and resource server routes. */

export const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
};

export const NO_STORE: Record<string, string> = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
};

export function json(body: unknown, init: ResponseInit = {}, extraHeaders: Record<string, string> = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  return new Response(JSON.stringify(body, null, 2), { ...init, headers });
}

export function html(body: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "text/html; charset=utf-8");
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  for (const [k, v] of Object.entries(NO_STORE)) headers.set(k, v);
  return new Response(body, { ...init, headers });
}

/** Permissive CORS for public, unauthenticated metadata and the token endpoint. */
export function withCors(response: Response, request: Request): Response {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    request.headers.get("Access-Control-Request-Headers") ?? "Content-Type, Authorization, MCP-Protocol-Version",
  );
  headers.set("Access-Control-Max-Age", "86400");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function preflight(request: Request): Response {
  return withCors(new Response(null, { status: 204 }), request);
}

/** RFC 6749 section 5.2 error body. */
export function oauthError(
  error: string,
  description: string,
  status = 400,
  extra: Record<string, string> = {},
): Response {
  return json({ error, error_description: description, ...extra }, { status }, NO_STORE);
}

export async function readForm(request: Request): Promise<URLSearchParams> {
  const type = request.headers.get("Content-Type") ?? "";
  if (!type.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    throw new FormError("Content-Type must be application/x-www-form-urlencoded");
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  return new URLSearchParams(new TextDecoder().decode(bytes));
}

export class FormError extends Error {}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Cryptographically random, URL-safe token of `bytes` bytes of entropy. */
export function randomToken(bytes = 32): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(buf);
}

export function base64url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += BASE64URL[(n >> 18) & 63]! + BASE64URL[(n >> 12) & 63]! + BASE64URL[(n >> 6) & 63]! + BASE64URL[n & 63]!;
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i]! << 16;
    out += BASE64URL[(n >> 18) & 63]! + BASE64URL[(n >> 12) & 63]!;
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += BASE64URL[(n >> 18) & 63]! + BASE64URL[(n >> 12) & 63]! + BASE64URL[(n >> 6) & 63]!;
  }
  return out;
}

export async function sha256Base64url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return base64url(new Uint8Array(digest));
}

/** Constant-time string comparison for short secrets. */
export function timingSafeEqual(a: string, b: string): boolean {
  const ab = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i]! ^ bb[i]!;
  return diff === 0;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
