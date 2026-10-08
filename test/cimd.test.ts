import { describe, expect, it } from "vitest";
import {
  cacheLifetimeSeconds,
  CIMD_LIMITS,
  CimdError,
  fetchClientMetadata,
  looksLikeClientIdUrl,
  redirectUriIsRegistered,
  validateClientIdUrl,
  validateClientMetadataDocument,
  type ClientIdPolicy,
  type FetchClientMetadataDeps,
} from "../src/auth/cimd.js";

const PUBLIC: ClientIdPolicy = { allowLoopbackHttp: false, allowedHosts: [] };
const DEV: ClientIdPolicy = { allowLoopbackHttp: true, allowedHosts: [] };
const DOC_URL = "https://app.example.com/oauth/client.json";

function validDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: DOC_URL,
    client_name: "Example MCP Client",
    client_uri: "https://app.example.com",
    redirect_uris: ["http://127.0.0.1:3000/callback", "https://app.example.com/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...overrides,
  };
}

function expectCimdError(fn: () => unknown, pattern: RegExp): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(CimdError);
    expect((error as CimdError).message).toMatch(pattern);
    return;
  }
  throw new Error(`expected a CimdError matching ${pattern}`);
}

describe("client_id URL rules (draft section 3)", () => {
  it("accepts an https URL with a path", () => {
    expect(validateClientIdUrl(DOC_URL, PUBLIC).href).toBe(DOC_URL);
    expect(validateClientIdUrl("https://app.example.com:8443/client.json?v=2", PUBLIC).port).toBe("8443");
  });

  it("requires the https scheme", () => {
    expectCimdError(() => validateClientIdUrl("http://app.example.com/client.json", PUBLIC), /https/);
    expectCimdError(() => validateClientIdUrl("ftp://app.example.com/client.json", PUBLIC), /https/);
  });

  it("requires a path component", () => {
    expectCimdError(() => validateClientIdUrl("https://app.example.com/", PUBLIC), /path component|normalised/);
    expectCimdError(() => validateClientIdUrl("https://app.example.com", PUBLIC), /path component|normalised/);
  });

  it("rejects dot segments, fragments, and userinfo", () => {
    expectCimdError(() => validateClientIdUrl("https://app.example.com/a/../client.json", PUBLIC), /dot|normalised/);
    expectCimdError(() => validateClientIdUrl("https://app.example.com/client.json#frag", PUBLIC), /fragment/);
    expectCimdError(() => validateClientIdUrl("https://user:pw@app.example.com/client.json", PUBLIC), /username or password/);
  });

  it("rejects values the URL parser would normalise, so simple string comparison can hold", () => {
    expectCimdError(() => validateClientIdUrl("HTTPS://app.example.com/client.json", PUBLIC), /normalised/);
    expectCimdError(() => validateClientIdUrl("https://App.Example.com/client.json", PUBLIC), /normalised/);
  });

  it("rejects over-long identifiers and non-URLs", () => {
    expectCimdError(() => validateClientIdUrl(`https://app.example.com/${"a".repeat(CIMD_LIMITS.maxClientIdLength)}`, PUBLIC), /too long/);
    expectCimdError(() => validateClientIdUrl("not a url", PUBLIC), /not a valid URL/);
  });

  it("refuses IP literals and non-public hostnames", () => {
    expectCimdError(() => validateClientIdUrl("https://203.0.113.9/client.json", PUBLIC), /DNS name/);
    expectCimdError(() => validateClientIdUrl("https://[2606:4700::1111]/client.json", PUBLIC), /DNS name/);
    expectCimdError(() => validateClientIdUrl("https://localhost/client.json", PUBLIC), /public DNS name/);
    expectCimdError(() => validateClientIdUrl("https://intranet/client.json", PUBLIC), /public DNS name/);
    expectCimdError(() => validateClientIdUrl("https://printer.local/client.json", PUBLIC), /public DNS name/);
    expectCimdError(() => validateClientIdUrl("https://db.internal/client.json", PUBLIC), /public DNS name/);
  });

  it("allows http loopback only in development mode", () => {
    expectCimdError(() => validateClientIdUrl("http://127.0.0.1:8976/client.json", PUBLIC), /https/);
    expect(validateClientIdUrl("http://127.0.0.1:8976/client.json", DEV).hostname).toBe("127.0.0.1");
    expect(validateClientIdUrl("http://localhost:8976/client.json", DEV).hostname).toBe("localhost");
    // Development mode does not open the door to arbitrary http hosts.
    expectCimdError(() => validateClientIdUrl("http://app.example.com/client.json", DEV), /https/);
  });

  it("enforces an allow list when configured", () => {
    const policy: ClientIdPolicy = { allowLoopbackHttp: false, allowedHosts: ["trusted.example.org"] };
    expect(validateClientIdUrl("https://trusted.example.org/c.json", policy).hostname).toBe("trusted.example.org");
    expectCimdError(() => validateClientIdUrl(DOC_URL, policy), /allow list/);
  });

  it("distinguishes URL client ids from opaque ids", () => {
    expect(looksLikeClientIdUrl(DOC_URL)).toBe(true);
    expect(looksLikeClientIdUrl("dcr_abc123")).toBe(false);
  });
});

describe("client metadata document rules (draft section 4.1, MCP client registration)", () => {
  it("accepts a well-formed document", () => {
    const metadata = validateClientMetadataDocument(validDocument(), DOC_URL);
    expect(metadata.client_name).toBe("Example MCP Client");
    expect(metadata.redirect_uris).toHaveLength(2);
  });

  it("requires client_id to match the document URL exactly", () => {
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_id: `${DOC_URL}?x=1` }), DOC_URL), /does not match/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_id: undefined }), DOC_URL), /does not match/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_id: "https://App.example.com/oauth/client.json" }), DOC_URL), /does not match/);
  });

  it("requires client_name and a non-empty redirect_uris array", () => {
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_name: undefined }), DOC_URL), /client_name/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_name: "" }), DOC_URL), /client_name/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ redirect_uris: [] }), DOC_URL), /redirect_uris/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ redirect_uris: "https://x.example/cb" }), DOC_URL), /redirect_uris/);
  });

  it("requires redirect URIs to be https or loopback http without fragments", () => {
    expectCimdError(() => validateClientMetadataDocument(validDocument({ redirect_uris: ["http://app.example.com/cb"] }), DOC_URL), /https or a loopback/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ redirect_uris: ["https://app.example.com/cb#x"] }), DOC_URL), /fragment/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ redirect_uris: ["/relative"] }), DOC_URL), /absolute/);
    expect(validateClientMetadataDocument(validDocument({ redirect_uris: ["http://localhost:6274/oauth/callback"] }), DOC_URL).redirect_uris).toEqual([
      "http://localhost:6274/oauth/callback",
    ]);
  });

  it("refuses shared secrets and non-public authentication methods", () => {
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_secret: "s3cret" }), DOC_URL), /client_secret/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ client_secret_expires_at: 0 }), DOC_URL), /client_secret/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ token_endpoint_auth_method: "client_secret_basic" }), DOC_URL), /shared-secret/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ token_endpoint_auth_method: "private_key_jwt" }), DOC_URL), /private_key_jwt/);
  });

  it("checks grant and response types when present", () => {
    expectCimdError(() => validateClientMetadataDocument(validDocument({ grant_types: ["client_credentials"] }), DOC_URL), /authorization_code/);
    expectCimdError(() => validateClientMetadataDocument(validDocument({ response_types: ["token"] }), DOC_URL), /code/);
    expect(validateClientMetadataDocument(validDocument({ grant_types: undefined, response_types: undefined }), DOC_URL).client_id).toBe(DOC_URL);
  });

  it("rejects non-object documents", () => {
    expectCimdError(() => validateClientMetadataDocument([], DOC_URL), /JSON object/);
    expectCimdError(() => validateClientMetadataDocument("x", DOC_URL), /JSON object/);
    expectCimdError(() => validateClientMetadataDocument(null, DOC_URL), /JSON object/);
  });

  it("matches redirect_uri by exact string comparison", () => {
    const metadata = validateClientMetadataDocument(validDocument(), DOC_URL);
    expect(redirectUriIsRegistered(metadata, "http://127.0.0.1:3000/callback")).toBe(true);
    expect(redirectUriIsRegistered(metadata, "http://127.0.0.1:3000/callback/")).toBe(false);
    expect(redirectUriIsRegistered(metadata, "http://localhost:3000/callback")).toBe(false);
    expect(redirectUriIsRegistered(metadata, "http://127.0.0.1:3001/callback")).toBe(false);
  });
});

describe("cache lifetime (draft section 4.4)", () => {
  it("uses the default when there is no Cache-Control", () => {
    expect(cacheLifetimeSeconds(null)).toBe(CIMD_LIMITS.defaultCacheSeconds);
    expect(cacheLifetimeSeconds("public")).toBe(CIMD_LIMITS.defaultCacheSeconds);
  });
  it("respects no-store and clamps max-age to the configured bounds", () => {
    expect(cacheLifetimeSeconds("no-store")).toBe(0);
    expect(cacheLifetimeSeconds("max-age=0")).toBe(0);
    expect(cacheLifetimeSeconds("max-age=5")).toBe(CIMD_LIMITS.minCacheSeconds);
    expect(cacheLifetimeSeconds("public, max-age=600")).toBe(600);
    expect(cacheLifetimeSeconds("max-age=99999999")).toBe(CIMD_LIMITS.maxCacheSeconds);
  });
});

describe("fetching the document", () => {
  interface Remote {
    status?: number;
    headers?: Record<string, string>;
    body?: string | Uint8Array;
    throws?: Error;
  }

  function deps(remote: Remote, resolved: string[] = ["93.184.216.34"]) {
    const cache = new Map<string, { document: unknown; expiresAt: number }>();
    const calls: string[] = [];
    const d: FetchClientMetadataDeps = {
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push(typeof input === "string" ? input : input.toString());
        expect(init?.redirect).toBe("manual");
        if (remote.throws) throw remote.throws;
        return new Response(remote.body ?? JSON.stringify(validDocument()), {
          status: remote.status ?? 200,
          headers: { "Content-Type": "application/json", ...remote.headers },
        });
      }) as typeof fetch,
      resolve: async () => resolved,
      cache: {
        get: async (url) => cache.get(url),
        put: async (url, document, expiresAt) => void cache.set(url, { document, expiresAt }),
      },
      now: () => 1_000_000,
    };
    return { d, cache, calls };
  }

  const url = new URL(DOC_URL);

  it("fetches, validates, and caches a good document", async () => {
    const { d, cache, calls } = deps({ headers: { "Cache-Control": "max-age=600" } });
    const first = await fetchClientMetadata(url, PUBLIC, d);
    expect(first.fromCache).toBe(false);
    expect(first.metadata.client_name).toBe("Example MCP Client");
    expect(cache.get(DOC_URL)?.expiresAt).toBe(1_000_600);

    const second = await fetchClientMetadata(url, PUBLIC, d);
    expect(second.fromCache).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("does not cache when the document says no-store", async () => {
    const { d, cache } = deps({ headers: { "Cache-Control": "no-store" } });
    await fetchClientMetadata(url, PUBLIC, d);
    expect(cache.size).toBe(0);
  });

  it("never caches invalid documents", async () => {
    const { d, cache } = deps({ body: JSON.stringify(validDocument({ client_name: undefined })) });
    await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/client_name/);
    expect(cache.size).toBe(0);
  });

  it("does not follow redirects", async () => {
    const { d } = deps({ status: 302, headers: { Location: "https://evil.example/x.json" } });
    await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/redirect/);
  });

  it("requires HTTP 200", async () => {
    const { d } = deps({ status: 404 });
    await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/HTTP 404/);
  });

  it("requires a JSON content type", async () => {
    const { d } = deps({ headers: { "Content-Type": "text/plain" } });
    await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/application\/json/);
    const ok = deps({ headers: { "Content-Type": "application/oauth-client+json; charset=utf-8" } });
    await expect(fetchClientMetadata(url, PUBLIC, ok.d)).resolves.toBeTruthy();
  });

  it("enforces the size limit from Content-Length and from the body", async () => {
    const declared = deps({ headers: { "Content-Length": String(CIMD_LIMITS.maxDocumentBytes + 1) } });
    await expect(fetchClientMetadata(url, PUBLIC, declared.d)).rejects.toThrow(/exceeds/);

    const padded = JSON.stringify(validDocument({ padding: "x".repeat(CIMD_LIMITS.maxDocumentBytes) }));
    const streamed = deps({ body: padded });
    await expect(fetchClientMetadata(url, PUBLIC, streamed.d)).rejects.toThrow(/exceeds/);
  });

  it("rejects malformed JSON", async () => {
    const { d } = deps({ body: "{not json" });
    await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/valid JSON/);
  });

  it("reports timeouts and network failures as invalid_client", async () => {
    const timeout = new Error("The operation was aborted due to timeout");
    timeout.name = "TimeoutError";
    await expect(fetchClientMetadata(url, PUBLIC, deps({ throws: timeout }).d)).rejects.toThrow(/timed out/);
    await expect(fetchClientMetadata(url, PUBLIC, deps({ throws: new Error("ECONNRESET") }).d)).rejects.toThrow(/failed/);
  });

  it("refuses hosts that resolve to private, loopback, or link-local addresses (SSRF)", async () => {
    for (const address of ["127.0.0.1", "10.1.2.3", "192.168.1.10", "172.16.0.1", "169.254.169.254", "::1", "fd00::1", "::ffff:10.0.0.1"]) {
      const { d, calls } = deps({}, [address]);
      await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/private or special-use/);
      expect(calls).toHaveLength(0);
    }
    // One bad address among good ones is enough to refuse.
    const mixed = deps({}, ["93.184.216.34", "10.0.0.1"]);
    await expect(fetchClientMetadata(url, PUBLIC, mixed.d)).rejects.toThrow(/private or special-use/);
  });

  it("refuses hosts that do not resolve", async () => {
    const { d } = deps({}, []);
    await expect(fetchClientMetadata(url, PUBLIC, d)).rejects.toThrow(/does not resolve/);
  });

  it("skips DNS checks for loopback client ids in development mode only", async () => {
    const local = new URL("http://127.0.0.1:8976/client-metadata.json");
    const body = JSON.stringify(validDocument({ client_id: local.href, redirect_uris: ["http://127.0.0.1:8976/callback"] }));
    const { d } = deps({ body });
    d.resolve = async () => {
      throw new Error("should not resolve");
    };
    const result = await fetchClientMetadata(local, DEV, d);
    expect(result.metadata.client_id).toBe(local.href);
  });
});
