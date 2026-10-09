/**
 * Sample Client ID Metadata Documents this Worker serves at /examples/*.json
 * so MCP Inspector can run against a deployed copy without hosting its own file.
 *
 * Cloudflare does not loop a Worker's fetch() back to the same workers.dev
 * hostname (same-zone Worker-to-Worker fetch requires a service binding).
 * Authorization therefore builds these documents in-process when client_id is
 * this issuer plus one of the paths below, then runs the same validators as a
 * fetched document. Third-party client_id URLs still go over the network.
 */

export const INSPECTOR_WEB_PATH = "/examples/inspector-web.json";
export const INSPECTOR_CLI_PATH = "/examples/inspector-cli.json";

const EXAMPLES: Record<string, { client_name: string; redirect_uris: string[] }> = {
  [INSPECTOR_WEB_PATH]: {
    client_name: "MCP Inspector (web)",
    redirect_uris: ["http://localhost:6274/oauth/callback"],
  },
  [INSPECTOR_CLI_PATH]: {
    client_name: "MCP Inspector (CLI/TUI)",
    redirect_uris: ["http://127.0.0.1:6276/oauth/callback"],
  },
};

/** Document this Worker would serve at `documentUrl`, or undefined if that URL is not one of ours. */
export function buildExampleClientMetadata(documentUrl: string): Record<string, unknown> | undefined {
  let url: URL;
  try {
    url = new URL(documentUrl);
  } catch {
    return undefined;
  }
  const spec = EXAMPLES[url.pathname];
  if (!spec) return undefined;
  const canonical = `${url.origin}${url.pathname}`;
  if (documentUrl !== canonical) return undefined;
  return {
    client_id: canonical,
    client_name: spec.client_name,
    client_uri: "https://modelcontextprotocol.io/docs/tools/inspector",
    redirect_uris: spec.redirect_uris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
}

/** True when this client_id is an example document hosted by `issuer`. */
export function isSameOriginExampleClientId(clientIdUrl: URL, issuer: string): boolean {
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    return false;
  }
  return clientIdUrl.origin === issuerUrl.origin && buildExampleClientMetadata(clientIdUrl.href) !== undefined;
}
