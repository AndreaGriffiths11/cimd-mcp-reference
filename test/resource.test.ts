import { describe, expect, it } from "vitest";
import { audienceMatches, canonicalizeResource, checkRequestedResource } from "../src/auth/resource.js";

const RESOURCE = "https://mcp.example.com/mcp";

describe("RFC 8707 resource indicator", () => {
  it("canonicalises scheme and host case and trailing slashes", () => {
    expect(canonicalizeResource("HTTPS://MCP.Example.com/mcp")).toBe(RESOURCE);
    expect(canonicalizeResource("https://mcp.example.com/mcp/")).toBe(RESOURCE);
    expect(canonicalizeResource("https://mcp.example.com")).toBe("https://mcp.example.com");
    expect(canonicalizeResource("https://mcp.example.com/")).toBe("https://mcp.example.com");
  });

  it("refuses fragments, relative values, and non-http schemes", () => {
    expect(canonicalizeResource("https://mcp.example.com/mcp#frag")).toBeUndefined();
    expect(canonicalizeResource("mcp.example.com/mcp")).toBeUndefined();
    expect(canonicalizeResource("urn:example:mcp")).toBeUndefined();
  });

  it("requires the parameter on authorization and token requests", () => {
    const missing = checkRequestedResource(null, RESOURCE);
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error).toMatch(/required/);
  });

  it("only accepts this server's own resource", () => {
    expect(checkRequestedResource(RESOURCE, RESOURCE)).toEqual({ ok: true, resource: RESOURCE });
    expect(checkRequestedResource("https://MCP.example.com/mcp/", RESOURCE)).toEqual({ ok: true, resource: RESOURCE });
    expect(checkRequestedResource("https://mcp.example.com", RESOURCE).ok).toBe(false);
    expect(checkRequestedResource("https://mcp.example.com/other", RESOURCE).ok).toBe(false);
    expect(checkRequestedResource("https://other.example.com/mcp", RESOURCE).ok).toBe(false);
    expect(checkRequestedResource("https://mcp.example.com:8443/mcp", RESOURCE).ok).toBe(false);
  });
});

describe("token audience check at the MCP endpoint", () => {
  it("accepts tokens whose audience is this server", () => {
    expect(audienceMatches(RESOURCE, RESOURCE)).toBe(true);
    expect(audienceMatches("https://mcp.example.com/mcp/", RESOURCE)).toBe(true);
  });
  it("refuses tokens issued for anything else", () => {
    expect(audienceMatches("https://mcp.example.com", RESOURCE)).toBe(false);
    expect(audienceMatches("https://api.example.com/mcp", RESOURCE)).toBe(false);
    expect(audienceMatches("https://mcp.example.com/mcp/v2", RESOURCE)).toBe(false);
    expect(audienceMatches("garbage", RESOURCE)).toBe(false);
  });
});
