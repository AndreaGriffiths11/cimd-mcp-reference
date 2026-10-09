#!/usr/bin/env node
/**
 * Example MCP client that authenticates with a Client ID Metadata Document.
 *
 * It does the whole dance by hand so every step is visible:
 *
 *   1. call the MCP endpoint without a token, read the 401 challenge
 *   2. fetch protected resource metadata (RFC 9728)
 *   3. fetch authorization server metadata (RFC 8414) and check
 *      client_id_metadata_document_supported and PKCE S256
 *   4. host (or point at) a Client ID Metadata Document and use its URL as client_id
 *   5. send the user to /authorize with PKCE and the resource indicator
 *   6. receive the callback, validate state and iss (RFC 9207)
 *   7. exchange the code at /token
 *   8. call MCP tools with the access token using @modelcontextprotocol/client
 *   9. rotate the refresh token once and call a tool again
 *
 * Usage:
 *   node examples/client/cimd-client.mjs [options]
 *
 * Options:
 *   --server <url>       MCP endpoint (default http://localhost:8787/mcp)
 *   --client-id <url>    Use an existing https Client ID Metadata Document instead of
 *                        hosting one locally. Its redirect_uris must include this
 *                        script's callback URL (printed at startup).
 *   --port <n>           Local port for the metadata document and callback (default 8976)
 *   --no-browser         Print the authorization URL instead of opening a browser
 *   --auto-consent       Approve the consent screen from this script. Only for scripted
 *                        tests against a server you run yourself.
 *
 * Requires Node.js 20 or newer. No dependencies beyond this repository's package.json.
 */

import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/client";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const args = parseArgs(process.argv.slice(2));
const serverUrl = new URL(args.server ?? "http://localhost:8787/mcp");
const port = Number(args.port ?? 8976);
const callbackUrl = `http://127.0.0.1:${port}/callback`;
const hostedClientId = `http://127.0.0.1:${port}/client-metadata.json`;
const clientId = args["client-id"] ?? hostedClientId;

/** The Client ID Metadata Document this script publishes about itself. */
const clientMetadataDocument = {
  client_id: hostedClientId,
  client_name: "CIMD example client",
  client_uri: "https://github.com/AndreaGriffiths11/cimd-mcp-reference",
  redirect_uris: [callbackUrl],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

const log = (step, message) => console.log(`\n[${step}] ${message}`);

main().catch((error) => {
  console.error(`\nFailed: ${error.message}`);
  process.exit(1);
});

async function main() {
  const local = await startLocalServer();
  try {
    if (clientId === hostedClientId) {
      log("0", `Hosting my Client ID Metadata Document at ${hostedClientId}`);
      if (!/^http:\/\/(127\.0\.0\.1|localhost)/.test(serverUrl.origin)) {
        console.log(
          "    Note: the server is not on loopback, so it will refuse an http:// client_id.\n" +
            "    Publish client-metadata.json on any https host and pass --client-id <url>.",
        );
      }
    } else {
      log("0", `Using Client ID Metadata Document ${clientId} (redirect_uri ${callbackUrl})`);
    }

    // 1. Unauthenticated request. The 401 tells us where the metadata lives.
    log("1", `POST ${serverUrl} without a token`);
    const challenge = await probe(serverUrl);
    console.log(`    WWW-Authenticate: ${challenge.header}`);

    // 2. Protected resource metadata.
    const prmUrl = challenge.params.resource_metadata ?? `${serverUrl.origin}/.well-known/oauth-protected-resource${serverUrl.pathname}`;
    log("2", `GET ${prmUrl}`);
    const prm = await getJson(prmUrl);
    const resource = prm.resource;
    const issuer = prm.authorization_servers?.[0];
    if (!resource || !issuer) throw new Error("protected resource metadata is missing resource or authorization_servers");
    console.log(`    resource: ${resource}\n    authorization server: ${issuer}`);

    // 3. Authorization server metadata.
    const { metadata: as, url: asUrl } = await discoverAuthorizationServer(issuer);
    log("3", `GET ${asUrl}`);
    if (as.issuer !== issuer) throw new Error(`issuer mismatch: metadata says ${as.issuer}, expected ${issuer}`);
    if (!as.code_challenge_methods_supported?.includes("S256")) throw new Error("authorization server does not advertise PKCE S256");
    if (as.client_id_metadata_document_supported !== true) {
      const fallback = as.registration_endpoint
        ? "It offers Dynamic Client Registration, which MCP deprecated in 2026-07-28."
        : "It offers no registration mechanism, so you would need a pre-registered client.";
      throw new Error(`authorization server does not support Client ID Metadata Documents. ${fallback}`);
    }
    console.log(`    client_id_metadata_document_supported: true\n    authorization_endpoint: ${as.authorization_endpoint}\n    token_endpoint: ${as.token_endpoint}`);

    // 4 and 5. Authorization request with PKCE, state, and the resource indicator.
    const codeVerifier = base64url(randomBytes(32));
    const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest());
    const state = base64url(randomBytes(16));
    const scope = challenge.params.scope ?? (prm.scopes_supported ?? []).join(" ");
    const authorizeUrl = new URL(as.authorization_endpoint);
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: callbackUrl,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope,
      resource,
    }).toString();
    log("4", `client_id is a URL: ${clientId}`);
    log("5", `Authorization request\n    ${authorizeUrl}`);

    const callbackPromise = local.waitForCallback();
    if (args["auto-consent"]) {
      console.log("    --auto-consent: approving the consent screen programmatically");
      await autoApprove(authorizeUrl);
    } else if (args["no-browser"]) {
      console.log("    Open the URL above in your browser and approve the request.");
    } else {
      console.log("    Opening your browser. Approve the request to continue.");
      openBrowser(authorizeUrl.href);
    }

    // 6. Callback.
    const cb = await callbackPromise;
    log("6", `Callback received at ${callbackUrl}`);
    if (cb.get("state") !== state) throw new Error("state mismatch; discarding the response");
    const iss = cb.get("iss");
    if (as.authorization_response_iss_parameter_supported === true && iss === null) {
      throw new Error("authorization response is missing iss although the server advertises RFC 9207 support");
    }
    if (iss !== null && iss !== issuer) throw new Error(`iss mismatch: ${iss} is not ${issuer} (possible mix-up attack)`);
    if (cb.get("error")) throw new Error(`${cb.get("error")}: ${cb.get("error_description") ?? ""}`);
    const code = cb.get("code");
    if (!code) throw new Error("callback did not include a code");
    console.log(`    state ok, iss ok (${iss}), code received`);

    // 7. Token exchange.
    log("7", `POST ${as.token_endpoint}`);
    let tokens = await postForm(as.token_endpoint, {
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl,
      client_id: clientId,
      code_verifier: codeVerifier,
      resource,
    });
    console.log(`    token_type=${tokens.token_type} expires_in=${tokens.expires_in} scope="${tokens.scope}" refresh_token=${tokens.refresh_token ? "yes" : "no"}`);

    // 8. Call MCP tools with the access token.
    log("8", `MCP calls against ${serverUrl}`);
    await callTools(tokens.access_token);

    // 9. Refresh token rotation.
    if (tokens.refresh_token) {
      log("9", "Refreshing the access token (rotation: the old refresh token is now invalid)");
      tokens = await postForm(as.token_endpoint, {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: clientId,
        resource,
      });
      const result = await callTool(tokens.access_token, "current_time", { timeZone: "UTC" });
      console.log(`    current_time with the new token: ${textOf(result)}`);
    }

    console.log("\nDone. The client never registered anything at the server; its identity was the URL of its metadata document.");
  } finally {
    local.close();
  }
}

// --- MCP calls -----------------------------------------------------------------------

/** Bearer-token transport: the OAuth flow above already produced the token, so no authProvider is needed. */
function connectWithToken(accessToken) {
  const client = new Client(
    { name: "cimd-example-client", version: "0.1.0" },
    // Pin the 2026-07-28 stateless protocol. Remove this to let the SDK negotiate with older servers.
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  const transport = new StreamableHTTPClientTransport(serverUrl, {
    requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
  });
  return client.connect(transport).then(() => client);
}

async function callTools(accessToken) {
  const client = await connectWithToken(accessToken);
  try {
    const { tools } = await client.listTools();
    console.log(`    tools: ${tools.map((t) => t.name).join(", ")}`);
    const whoami = await client.callTool({ name: "whoami", arguments: {} });
    console.log(`    whoami:\n${indent(textOf(whoami), 8)}`);
    const added = await client.callTool({ name: "add_note", arguments: { text: `Authorized via CIMD at ${new Date().toISOString()}` } });
    console.log(`    add_note: ${textOf(added)}`);
    const notes = await client.callTool({ name: "list_notes", arguments: {} });
    console.log(`    list_notes:\n${indent(textOf(notes), 8)}`);
  } finally {
    await client.close();
  }
}

async function callTool(accessToken, name, toolArgs) {
  const client = await connectWithToken(accessToken);
  try {
    return await client.callTool({ name, arguments: toolArgs });
  } finally {
    await client.close();
  }
}

function textOf(result) {
  return (result.content ?? [])
    .filter((c) => c.type === "text")
    .map((c) => c.text)
    .join("\n");
}

// --- discovery helpers ---------------------------------------------------------------------

async function probe(url) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": "2026-07-28",
      "Mcp-Method": "tools/list",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientInfo": { name: "cimd-example-client", version: "0.1.0" },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
  if (response.status !== 401) throw new Error(`expected 401 from the MCP endpoint, got ${response.status}`);
  const header = response.headers.get("WWW-Authenticate") ?? "";
  return { header, params: parseChallenge(header) };
}

function parseChallenge(header) {
  const params = {};
  for (const match of header.matchAll(/([a-zA-Z_]+)="((?:[^"\\]|\\.)*)"/g)) {
    params[match[1]] = match[2].replace(/\\(.)/g, "$1");
  }
  return params;
}

/** RFC 8414 section 3.1 with the MCP priority order for issuers with or without a path. */
async function discoverAuthorizationServer(issuer) {
  const url = new URL(issuer);
  const path = url.pathname.replace(/\/$/, "");
  const candidates = path
    ? [`${url.origin}/.well-known/oauth-authorization-server${path}`, `${url.origin}/.well-known/openid-configuration${path}`, `${url.origin}${path}/.well-known/openid-configuration`]
    : [`${url.origin}/.well-known/oauth-authorization-server`, `${url.origin}/.well-known/openid-configuration`];
  for (const candidate of candidates) {
    const response = await fetch(candidate);
    if (response.ok) return { metadata: await response.json(), url: candidate };
  }
  throw new Error(`no authorization server metadata found for ${issuer}`);
}

async function getJson(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`GET ${url} returned ${response.status}`);
  return response.json();
}

async function postForm(url, fields) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams(fields),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`${url} returned ${response.status}: ${body.error} (${body.error_description ?? ""})`);
  return body;
}

/** Drives the consent form the way a browser would. Test automation only. */
async function autoApprove(authorizeUrl) {
  const page = await fetch(authorizeUrl, { redirect: "manual" });
  if (page.status !== 200) {
    throw new Error(`authorize returned ${page.status}: ${(await page.text()).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300)}`);
  }
  const htmlText = await page.text();
  const requestId = /name="request_id" value="([^"]+)"/.exec(htmlText)?.[1];
  if (!requestId) throw new Error("could not find request_id on the consent page");
  const decision = await fetch(new URL("/authorize/decision", authorizeUrl), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: requestId, decision: "approve" }),
    redirect: "manual",
  });
  const location = decision.headers.get("Location");
  if (decision.status !== 302 || !location) throw new Error(`decision returned ${decision.status}`);
  await fetch(location); // deliver the code to our own callback listener
}

// --- local server: metadata document + callback -------------------------------------------------

function startLocalServer() {
  let resolveCallback;
  const callback = new Promise((resolve) => (resolveCallback = resolve));
  const server = createServer((req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    if (url.pathname === "/client-metadata.json") {
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "max-age=300" });
      res.end(JSON.stringify(clientMetadataDocument, null, 2));
      return;
    }
    if (url.pathname === "/callback") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<!doctype html><title>Done</title><p>Authorization received. You can close this tab and return to the terminal.</p>");
      resolveCallback(url.searchParams);
      return;
    }
    res.writeHead(404).end();
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      resolve({
        waitForCallback: () => callback,
        close: () => server.close(),
      });
    });
  });
}

function openBrowser(url) {
  const [cmd, cmdArgs] =
    process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  const child = spawn(cmd, cmdArgs, { stdio: "ignore", detached: true });
  child.on("error", () => console.log(`    Could not open a browser. Visit:\n    ${url}`));
  child.unref();
}

// --- small utilities ---------------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
}

function base64url(buffer) {
  return buffer.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function indent(text, spaces) {
  const pad = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => pad + line)
    .join("\n");
}
