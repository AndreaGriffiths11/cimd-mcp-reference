import type { Config, Env } from "../env.js";
import { sha256Base64url } from "../http.js";
import { authStore } from "../store/auth-store.js";
import {
  type ClientMetadata,
  CimdError,
  fetchClientMetadata,
  looksLikeClientIdUrl,
  validateClientIdUrl,
  validateClientMetadataDocument,
} from "./cimd.js";
import { resolveWithDoH } from "./ssrf.js";

export interface ResolvedClient {
  clientId: string;
  metadata: ClientMetadata;
  registration: "cimd" | "dcr";
  fromCache: boolean;
}

/**
 * Turns a `client_id` into client metadata.
 *
 * URL-formatted identifiers take the Client ID Metadata Document path. Anything
 * else is looked up among clients created through the deprecated Dynamic Client
 * Registration endpoint, when that path is enabled. The draft (section 6.9)
 * notes that generated ids must never start with `https://` so the two spaces
 * cannot collide; this server generates opaque random ids.
 */
export async function resolveClient(clientId: string, config: Config, env: Env): Promise<ResolvedClient> {
  const store = authStore(env);
  if (looksLikeClientIdUrl(clientId)) {
    const policy = { allowLoopbackHttp: config.allowLoopbackClientIds, allowedHosts: config.cimdAllowedHosts };
    const url = validateClientIdUrl(clientId, policy);
    const { metadata, fromCache } = await fetchClientMetadata(url, policy, {
      fetch: (input, init) => fetch(input, init),
      resolve: resolveWithDoH,
      cache: {
        async get(documentUrl) {
          const cached = await store.getCachedClientMetadata(await sha256Base64url(documentUrl));
          return cached ? { document: JSON.parse(cached.documentJson) as unknown, expiresAt: cached.expiresAt } : undefined;
        },
        async put(documentUrl, document, expiresAt) {
          await store.putCachedClientMetadata(await sha256Base64url(documentUrl), { documentJson: JSON.stringify(document), expiresAt });
        },
      },
    });
    return { clientId, metadata, registration: "cimd", fromCache };
  }

  if (!config.deprecatedDcrEnabled) {
    throw new CimdError(
      "invalid_client",
      "client_id must be an https URL pointing at a Client ID Metadata Document (this server does not use pre-registered clients)",
    );
  }
  const registered = await store.getRegisteredClient(clientId);
  if (!registered) throw new CimdError("invalid_client", "unknown client_id");
  const metadata = validateClientMetadataDocument({ ...(JSON.parse(registered.metadataJson) as object), client_id: clientId }, clientId);
  return { clientId, metadata, registration: "dcr", fromCache: false };
}
