import { describe, expect, it } from "vitest";
import { renderConsent } from "../src/auth/consent-page.js";

const base = {
  requestId: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  clientId: "https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/examples/inspector-web.json",
  clientName: "MCP Inspector (web)",
  clientUri: "https://modelcontextprotocol.io/docs/tools/inspector",
  redirectUri: "http://localhost:6274/oauth/callback",
  scopes: ["mcp:tools"],
  resource: "https://cimd-mcp-reference.andrea-oauth-demos.workers.dev/mcp",
  registration: "cimd" as const,
};

describe("consent screen", () => {
  it("shows a password field only when requirePassword is set", () => {
    const open = renderConsent({ ...base, requirePassword: false });
    expect(open).not.toContain('type="password"');
    expect(open).toContain("MCP Inspector (web)");

    const gated = renderConsent({ ...base, requirePassword: true });
    expect(gated).toContain('type="password"');
    expect(gated).toContain("Consent password");
    expect(gated).toContain("MCP Inspector (web)");
    expect(gated).toContain("andrea-oauth-demos.workers.dev");
  });
});
