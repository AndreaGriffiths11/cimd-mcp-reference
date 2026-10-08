/**
 * RFC 8707 resource indicators and audience binding.
 *
 * The MCP spec requires clients to send `resource` on the authorization and
 * token requests, set to the canonical URI of the MCP server. This server
 * issues tokens whose audience is exactly that URI and the MCP endpoint
 * refuses any token whose audience is different.
 */

export type ResourceCheck = { ok: true; resource: string } | { ok: false; error: string };

/**
 * Canonical form for comparison: lowercase scheme and host, no fragment, no
 * trailing slash. The MCP spec asks implementations to accept uppercase
 * scheme/host for robustness while recommending the lowercase form.
 */
export function canonicalizeResource(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.hash !== "" || value.includes("#")) return undefined;
  if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
  url.hash = "";
  return url.href.replace(/\/+$/, "");
}

/**
 * Validates the `resource` parameter of an authorization or token request
 * against the one resource this server protects.
 */
export function checkRequestedResource(requested: string | null, expectedResource: string): ResourceCheck {
  if (!requested) {
    return { ok: false, error: "resource parameter is required (RFC 8707); MCP clients must send the canonical MCP server URI" };
  }
  const canonical = canonicalizeResource(requested);
  if (!canonical) return { ok: false, error: "resource must be an absolute https URI without a fragment" };
  if (canonical !== canonicalizeResource(expectedResource)) {
    return { ok: false, error: `this authorization server only issues tokens for ${expectedResource}` };
  }
  return { ok: true, resource: expectedResource };
}

/** Resource-server side: does the token's audience name this MCP server? */
export function audienceMatches(tokenAudience: string, expectedResource: string): boolean {
  const a = canonicalizeResource(tokenAudience);
  const b = canonicalizeResource(expectedResource);
  return a !== undefined && a === b;
}
