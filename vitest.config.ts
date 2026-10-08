import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

/**
 * Fake "internet" for integration tests. Every outbound fetch() the Worker
 * makes during tests (Client ID Metadata Documents, DNS over HTTPS) lands here,
 * so the test suite never touches the network.
 */
const RESOLVES_TO: Record<string, string[]> = {
  "good-client.example.com": ["93.184.216.34"],
  "mismatch-client.example.com": ["93.184.216.34"],
  "redirecting-client.example.com": ["93.184.216.34"],
  "private-client.example.com": ["10.0.0.5"],
  "metadata-client.example.com": ["93.184.216.34", "2606:4700:4700::1111"],
};

function clientDocument(clientId: string, extra: Record<string, unknown> = {}) {
  return {
    client_id: clientId,
    client_name: "Integration Test Client",
    client_uri: "https://good-client.example.com",
    redirect_uris: ["http://127.0.0.1:3000/callback", "https://good-client.example.com/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...extra,
  };
}

async function fakeInternet(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const json = (body: unknown, init: ResponseInit = {}) =>
    new Response(JSON.stringify(body), { ...init, headers: { "Content-Type": "application/json", ...(init.headers ?? {}) } });

  if (url.hostname === "cloudflare-dns.com" && url.pathname === "/dns-query") {
    const name = url.searchParams.get("name") ?? "";
    const type = url.searchParams.get("type");
    const answers = (RESOLVES_TO[name] ?? []).filter((a) => (type === "AAAA") === a.includes(":"));
    return json({ Status: 0, Answer: answers.map((data) => ({ name, type: type === "AAAA" ? 28 : 1, TTL: 60, data })) });
  }

  switch (`${url.hostname}${url.pathname}`) {
    case "127.0.0.1/client-metadata.json":
      return json(
        {
          client_id: url.href,
          client_name: "Loopback Dev Client",
          redirect_uris: [`http://127.0.0.1:${url.port}/callback`],
          token_endpoint_auth_method: "none",
        },
        { headers: { "Cache-Control": "no-store" } },
      );
    case "good-client.example.com/client.json":
      return json(clientDocument(url.href), { headers: { "Cache-Control": "max-age=600" } });
    case "mismatch-client.example.com/client.json":
      return json(clientDocument("https://good-client.example.com/client.json"));
    case "redirecting-client.example.com/client.json":
      return new Response(null, { status: 302, headers: { Location: "https://good-client.example.com/client.json" } });
    case "private-client.example.com/client.json":
      throw new Error("the Worker must not fetch from a host that resolves to a private address");
    default:
      return new Response("not found", { status: 404 });
  }
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ISSUER: "http://localhost:8787",
          DEV_ALLOW_LOOPBACK_CLIENT_IDS: "true",
          ENABLE_DEPRECATED_DCR: "false",
          ALLOWED_ORIGINS: "https://allowed-app.example.com",
          CIMD_ALLOWED_HOSTS: "",
        },
        outboundService: fakeInternet,
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
