import { type AuthInfo, OAuthError, OAuthErrorCode, type OAuthTokenVerifier } from "@modelcontextprotocol/server";
import type { Config, Env } from "../env.js";
import { sha256Base64url } from "../http.js";
import { audienceMatches } from "../auth/resource.js";
import { authStore } from "../store/auth-store.js";

/**
 * Resource-server token verification (OAuth 2.1 section 5.2, MCP "Token Handling").
 *
 * The MCP endpoint only accepts tokens that this Worker's own authorization
 * server issued for exactly this resource. The audience check happens twice on
 * purpose: here, so a token for another resource is refused even if a future
 * change forgets `expectedResource`, and again inside `requireBearerAuth`,
 * which compares `AuthInfo.resource` with the configured resource.
 */
export function tokenVerifier(env: Env, config: Config): OAuthTokenVerifier {
  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const record = await authStore(env).getAccessToken(await sha256Base64url(token));
      if (!record) throw new OAuthError(OAuthErrorCode.InvalidToken, "token is unknown, expired, or revoked");
      if (!audienceMatches(record.resource, config.resource)) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "token was not issued for this resource");
      }
      return {
        token,
        clientId: record.clientId,
        scopes: record.scope.split(" ").filter(Boolean),
        expiresAt: record.expiresAt,
        resource: new URL(record.resource),
        extra: { subject: record.subject, grantId: record.grantId },
      };
    },
  };
}
