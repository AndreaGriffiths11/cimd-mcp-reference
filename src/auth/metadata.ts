import { type Config, SCOPES_SUPPORTED } from "../env.js";

/**
 * RFC 8414 authorization server metadata, served at
 * /.well-known/oauth-authorization-server.
 *
 * `client_id_metadata_document_supported: true` is how a client learns it can
 * use its CIMD URL as client_id (CIMD draft section 5, MCP client registration).
 * `registration_endpoint` only appears when the deprecated DCR path is enabled,
 * which is what MCP clients key their DCR fallback on.
 */
export function authorizationServerMetadata(config: Config): Record<string, unknown> {
  const metadata: Record<string, unknown> = {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    revocation_endpoint: `${config.issuer}/revoke`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...SCOPES_SUPPORTED],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    service_documentation: "https://github.com/AndreaGriffiths11/cimd-mcp-reference#readme",
  };
  if (config.deprecatedDcrEnabled) metadata.registration_endpoint = `${config.issuer}/register`;
  return metadata;
}

/**
 * RFC 9728 protected resource metadata for the MCP endpoint, served at
 * /.well-known/oauth-protected-resource/mcp (path-aware) and at the root
 * well-known location. The `resource` value is the canonical URI clients
 * must send as the RFC 8707 `resource` parameter.
 */
export function protectedResourceMetadata(config: Config): Record<string, unknown> {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: [...SCOPES_SUPPORTED],
    bearer_methods_supported: ["header"],
    resource_name: "CIMD MCP reference server",
    resource_documentation: "https://github.com/AndreaGriffiths11/cimd-mcp-reference#readme",
  };
}
