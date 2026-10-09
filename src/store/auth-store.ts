import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env.js";

/**
 * Strongly consistent state for the authorization server and the demo tools.
 *
 * A single Durable Object instance (name "global") holds every record. That is
 * deliberate for a reference implementation: authorization codes and refresh
 * tokens must be single-use, and a Durable Object serialises access so
 * "read then delete" is atomic. Workers KV is eventually consistent and
 * cannot give that guarantee.
 *
 * Tokens and codes are stored under their SHA-256 hash, never in clear text.
 * Every record carries `expiresAt` (seconds since epoch) and an alarm sweeps
 * expired records periodically.
 */

export interface PendingAuthorization {
  clientId: string;
  clientName: string;
  clientUri: string | undefined;
  redirectUri: string;
  state: string | undefined;
  codeChallenge: string;
  scope: string;
  resource: string;
  registration: "cimd" | "dcr";
  expiresAt: number;
}

export interface AuthorizationCodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  resource: string;
  subject: string;
  grantId: string;
  expiresAt: number;
}

export interface AccessTokenRecord {
  clientId: string;
  scope: string;
  /** RFC 8707 audience: the canonical MCP resource URI the token was issued for. */
  resource: string;
  subject: string;
  grantId: string;
  expiresAt: number;
}

export interface RefreshTokenRecord extends AccessTokenRecord {}

/** Documents are stored as JSON text so records stay simple to pass across the Workers RPC boundary. */
export interface CachedClientMetadata {
  documentJson: string;
  expiresAt: number;
}

export interface RegisteredClient {
  clientId: string;
  metadataJson: string;
  expiresAt: number;
}

interface GrantRecord {
  /** Storage keys of every live token issued under this grant. */
  keys: string[];
  expiresAt: number;
}

export type RotateResult =
  | { ok: true; record: RefreshTokenRecord }
  | { ok: false; reason: "unknown" | "expired" | "reused" };

const SWEEP_INTERVAL_MS = 15 * 60 * 1000;
const now = () => Math.floor(Date.now() / 1000);

export class AuthStore extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    void ctx.blockConcurrencyWhile(async () => {
      if ((await ctx.storage.getAlarm()) === null) await ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
    });
  }

  // --- consent screen -------------------------------------------------------

  async savePendingAuthorization(id: string, data: PendingAuthorization): Promise<void> {
    await this.ctx.storage.put(`pending:${id}`, data);
  }

  /** Returns and deletes the pending request, so a consent form can only be submitted once. */
  async takePendingAuthorization(id: string): Promise<PendingAuthorization | undefined> {
    const key = `pending:${id}`;
    const data = await this.ctx.storage.get<PendingAuthorization>(key);
    if (!data) return undefined;
    await this.ctx.storage.delete(key);
    return data.expiresAt > now() ? data : undefined;
  }

  // --- authorization codes --------------------------------------------------

  async saveAuthorizationCode(codeHash: string, data: AuthorizationCodeRecord): Promise<void> {
    await this.ctx.storage.put(`code:${codeHash}`, data);
  }

  /** Single use: the record is deleted on first read, valid or not. */
  async consumeAuthorizationCode(codeHash: string): Promise<AuthorizationCodeRecord | undefined> {
    const key = `code:${codeHash}`;
    const data = await this.ctx.storage.get<AuthorizationCodeRecord>(key);
    if (!data) return undefined;
    await this.ctx.storage.delete(key);
    if (data.expiresAt <= now()) return undefined;
    return data;
  }

  // --- tokens -----------------------------------------------------------------

  async issueTokens(
    accessTokenHash: string,
    access: AccessTokenRecord,
    refreshTokenHash: string | undefined,
    refresh: RefreshTokenRecord | undefined,
    grantType: "authorization_code" | "refresh_token",
  ): Promise<boolean> {
    const grantKey = `grant:${access.grantId}`;
    const existingGrant = await this.ctx.storage.get<GrantRecord>(grantKey);
    // Replay can revoke the grant between refresh consumption and issuance.
    // Only an authorization code may create a new grant.
    if (grantType === "refresh_token" && (!existingGrant || existingGrant.expiresAt <= now())) return false;
    const grant = existingGrant ?? { keys: [], expiresAt: 0 };
    const entries: Record<string, unknown> = { [`at:${accessTokenHash}`]: access };
    grant.keys.push(`at:${accessTokenHash}`);
    grant.expiresAt = Math.max(grant.expiresAt, access.expiresAt);
    if (refreshTokenHash && refresh) {
      entries[`rt:${refreshTokenHash}`] = refresh;
      grant.keys.push(`rt:${refreshTokenHash}`);
      grant.expiresAt = Math.max(grant.expiresAt, refresh.expiresAt);
    }
    entries[grantKey] = grant;
    await this.ctx.storage.put(entries);
    return true;
  }

  async getAccessToken(accessTokenHash: string): Promise<AccessTokenRecord | undefined> {
    const data = await this.ctx.storage.get<AccessTokenRecord>(`at:${accessTokenHash}`);
    if (!data || data.expiresAt <= now()) return undefined;
    return data;
  }

  /**
   * Refresh token rotation (OAuth 2.1 section 4.3.1). The presented token is
   * invalidated. If a token that was already rotated is presented again, the
   * whole grant is revoked, because either the client or an attacker holds a
   * stolen copy.
   */
  async rotateRefreshToken(refreshTokenHash: string): Promise<RotateResult> {
    const key = `rt:${refreshTokenHash}`;
    const data = await this.ctx.storage.get<RefreshTokenRecord>(key);
    if (!data) {
      const used = await this.ctx.storage.get<{ grantId: string; expiresAt: number }>(`rtused:${refreshTokenHash}`);
      if (used) {
        await this.revokeGrant(used.grantId);
        return { ok: false, reason: "reused" };
      }
      return { ok: false, reason: "unknown" };
    }
    await this.ctx.storage.delete(key);
    await this.ctx.storage.put(`rtused:${refreshTokenHash}`, { grantId: data.grantId, expiresAt: data.expiresAt });
    if (data.expiresAt <= now()) return { ok: false, reason: "expired" };
    return { ok: true, record: data };
  }

  /** RFC 7009. Revoking a refresh token revokes the whole grant; revoking an access token revokes only itself. */
  async revokeToken(tokenHash: string): Promise<void> {
    const rt = await this.ctx.storage.get<RefreshTokenRecord>(`rt:${tokenHash}`);
    if (rt) {
      await this.revokeGrant(rt.grantId);
      return;
    }
    await this.ctx.storage.delete(`at:${tokenHash}`);
  }

  async revokeGrant(grantId: string): Promise<void> {
    const grantKey = `grant:${grantId}`;
    const grant = await this.ctx.storage.get<GrantRecord>(grantKey);
    if (grant) await this.ctx.storage.delete([...grant.keys, grantKey]);
  }

  // --- Client ID Metadata Document cache ---------------------------------------

  async getCachedClientMetadata(urlHash: string): Promise<CachedClientMetadata | undefined> {
    const data = await this.ctx.storage.get<CachedClientMetadata>(`cimd:${urlHash}`);
    if (!data || data.expiresAt <= now()) return undefined;
    return data;
  }

  async putCachedClientMetadata(urlHash: string, data: CachedClientMetadata): Promise<void> {
    await this.ctx.storage.put(`cimd:${urlHash}`, data);
  }

  // --- deprecated Dynamic Client Registration ----------------------------------

  async saveRegisteredClient(client: RegisteredClient): Promise<void> {
    await this.ctx.storage.put(`client:${client.clientId}`, client);
  }

  async getRegisteredClient(clientId: string): Promise<RegisteredClient | undefined> {
    const data = await this.ctx.storage.get<RegisteredClient>(`client:${clientId}`);
    if (!data || data.expiresAt <= now()) return undefined;
    return data;
  }

  // --- demo tool state -----------------------------------------------------------

  async addNote(subject: string, text: string): Promise<string[]> {
    const key = `notes:${subject}`;
    const notes = (await this.ctx.storage.get<string[]>(key)) ?? [];
    notes.push(text);
    await this.ctx.storage.put(key, notes.slice(-50));
    return notes;
  }

  async listNotes(subject: string): Promise<string[]> {
    return (await this.ctx.storage.get<string[]>(`notes:${subject}`)) ?? [];
  }

  // --- housekeeping ------------------------------------------------------------------

  override async alarm(): Promise<void> {
    const cutoff = now();
    const expired: string[] = [];
    for (const prefix of ["pending:", "code:", "at:", "rt:", "rtused:", "grant:", "cimd:", "client:"]) {
      const entries = await this.ctx.storage.list<{ expiresAt?: number }>({ prefix });
      for (const [key, value] of entries) {
        if (typeof value?.expiresAt === "number" && value.expiresAt <= cutoff) expired.push(key);
      }
    }
    for (let i = 0; i < expired.length; i += 128) await this.ctx.storage.delete(expired.slice(i, i + 128));
    await this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }
}

export function authStore(env: Env): DurableObjectStub<AuthStore> {
  return env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global"));
}
