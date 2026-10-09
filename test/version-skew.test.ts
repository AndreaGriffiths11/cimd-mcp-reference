/**
 * Worker and Durable Object code roll out separately. For a while after each
 * deploy the new Worker can call the single AuthStore while it still runs the
 * previous version, and the previous Worker can call the new AuthStore.
 * https://developers.cloudflare.com/durable-objects/platform/known-issues/#code-updates
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { issue } from "../src/auth/token.js";
import { sha256Base64url } from "../src/http.js";
import type { AuthStore } from "../src/store/auth-store.js";

const grant = {
  clientId: "https://good-client.example.com/client.json",
  scope: "mcp:tools",
  resource: "http://localhost:8787/mcp",
  subject: "demo-user",
};

type IssueStore = Parameters<typeof issue>[0];

describe("token issuance across a deploy", () => {
  it("issues tokens when the AuthStore still runs the version whose issueTokens returned void", async () => {
    const calls: unknown[][] = [];
    const previousStore = {
      // Before 8c994f4 issueTokens stored the records and resolved to undefined.
      issueTokens: async (...args: unknown[]) => {
        calls.push(args);
        return undefined;
      },
    } as unknown as IssueStore;
    const response = await issue(previousStore, { ...grant, grantId: crypto.randomUUID() }, "authorization_code");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string; refresh_token: string };
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(calls).toHaveLength(1);
  });

  it("still refuses issuance when the current AuthStore answers false", async () => {
    const currentStore = { issueTokens: async () => false } as unknown as IssueStore;
    const response = await issue(currentStore, { ...grant, grantId: crypto.randomUUID() }, "refresh_token");
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe("invalid_grant");
  });

  it("accepts a call from the previous Worker that omits grantType, over real Durable Object RPC", async () => {
    const stub = env.AUTH_STORE.get(env.AUTH_STORE.idFromName("global")) as DurableObjectStub<AuthStore>;
    const accessHash = await sha256Base64url(`skew-access-${crypto.randomUUID()}`);
    const refreshHash = await sha256Base64url(`skew-refresh-${crypto.randomUUID()}`);
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    const record = { ...grant, grantId: crypto.randomUUID(), expiresAt };
    const previousWorkerCall = stub.issueTokens as unknown as (...args: unknown[]) => Promise<unknown>;
    const issued = await previousWorkerCall(accessHash, record, refreshHash, record);
    expect(issued).not.toBe(false);
    expect(await stub.getAccessToken(accessHash)).toMatchObject({ grantId: record.grantId });
  });
});
