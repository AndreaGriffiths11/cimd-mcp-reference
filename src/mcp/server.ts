import { type AuthInfo, createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import type { Env } from "../env.js";
import { authStore } from "../store/auth-store.js";

/**
 * The MCP server behind /mcp. `createMcpHandler` runs the factory once per
 * request with the verified `AuthInfo`, so tools can read who is calling.
 *
 * The demo tools are intentionally small; the point of this repository is the
 * authorization path in front of them.
 */
export function createMcpFetchHandler(env: Env) {
  return createMcpHandler(({ authInfo }) => buildServer(env, authInfo), {
    // Serve both 2026-07-28 clients and 2025-era clients that still open with `initialize`.
    legacy: "stateless",
  });
}

function buildServer(env: Env, authInfo: AuthInfo | undefined): McpServer {
  const server = new McpServer(
    { name: "cimd-mcp-reference", version: "0.1.0" },
    {
      instructions:
        "Reference MCP server protected by OAuth with Client ID Metadata Documents. Use whoami to inspect the access token the client presented.",
    },
  );
  const subject = typeof authInfo?.extra?.subject === "string" ? authInfo.extra.subject : "anonymous";

  server.registerTool(
    "whoami",
    {
      description: "Describe the OAuth access token this request was authorized with: client, subject, scopes, audience, expiry.",
      inputSchema: z.object({}),
    },
    async () => {
      const summary = {
        subject,
        client_id: authInfo?.clientId ?? null,
        client_registration: authInfo?.clientId?.startsWith("http") ? "client-id-metadata-document" : "dynamic-client-registration",
        scopes: authInfo?.scopes ?? [],
        audience: authInfo?.resource?.href ?? null,
        expires_at: authInfo?.expiresAt ? new Date(authInfo.expiresAt * 1000).toISOString() : null,
      };
      return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }], structuredContent: summary };
    },
  );

  server.registerTool(
    "current_time",
    {
      description: "Current date and time, optionally in an IANA time zone such as America/New_York.",
      inputSchema: z.object({ timeZone: z.string().optional().describe("IANA time zone name. Defaults to UTC.") }),
    },
    async ({ timeZone }) => {
      const zone = timeZone ?? "UTC";
      let formatted: string;
      try {
        formatted = new Intl.DateTimeFormat("en-US", { dateStyle: "full", timeStyle: "long", timeZone: zone }).format(new Date());
      } catch {
        return { content: [{ type: "text", text: `Unknown time zone: ${zone}` }], isError: true };
      }
      return { content: [{ type: "text", text: `${formatted} (${new Date().toISOString()})` }] };
    },
  );

  server.registerTool(
    "add_note",
    {
      description: "Save a short note for the authenticated user. Notes are stored per subject, so they follow the user across clients.",
      inputSchema: z.object({ text: z.string().min(1).max(500) }),
    },
    async ({ text }) => {
      const notes = await authStore(env).addNote(subject, text);
      return { content: [{ type: "text", text: `Saved. ${notes.length} note(s) for ${subject}.` }] };
    },
  );

  server.registerTool(
    "list_notes",
    { description: "List the notes saved for the authenticated user.", inputSchema: z.object({}) },
    async () => {
      const notes = await authStore(env).listNotes(subject);
      const text = notes.length ? notes.map((n, i) => `${i + 1}. ${n}`).join("\n") : "No notes yet.";
      return { content: [{ type: "text", text }] };
    },
  );

  return server;
}
