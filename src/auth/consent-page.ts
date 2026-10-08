import { escapeHtml } from "../http.js";
import { isLoopbackHostname } from "../env.js";

const STYLE = `
  :root { color-scheme: light dark; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  body { margin: 0; display: flex; justify-content: center; padding: 3rem 1rem; background: Canvas; color: CanvasText; }
  main { max-width: 34rem; width: 100%; }
  h1 { font-size: 1.4rem; margin: 0 0 1rem; }
  .card { border: 1px solid color-mix(in srgb, CanvasText 20%, transparent); border-radius: 10px; padding: 1.25rem; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.4rem 1rem; margin: 1rem 0; }
  dt { opacity: 0.7; }
  dd { margin: 0; word-break: break-all; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.92em; }
  .host { font-weight: 600; }
  .warn { background: color-mix(in srgb, orange 18%, transparent); border-left: 4px solid orange; padding: 0.6rem 0.8rem; border-radius: 6px; margin: 0.8rem 0; }
  .err { background: color-mix(in srgb, crimson 15%, transparent); border-left: 4px solid crimson; padding: 0.6rem 0.8rem; border-radius: 6px; }
  .actions { display: flex; gap: 0.75rem; margin-top: 1.25rem; }
  button { font: inherit; padding: 0.6rem 1.2rem; border-radius: 8px; border: 1px solid transparent; cursor: pointer; }
  button.approve { background: #1a7f37; color: white; }
  button.deny { background: transparent; border-color: color-mix(in srgb, CanvasText 30%, transparent); color: inherit; }
  label { display: block; margin-top: 1rem; }
  input[type=password] { font: inherit; padding: 0.5rem; width: 100%; box-sizing: border-box; margin-top: 0.3rem; }
  footer { margin-top: 1.5rem; font-size: 0.85rem; opacity: 0.7; }
`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title><style>${STYLE}</style></head>
<body><main>${body}
<footer>CIMD MCP reference server. The client identity above comes from the Client ID Metadata Document at the <code>client_id</code> URL.</footer>
</main></body></html>`;
}

export interface ConsentView {
  requestId: string;
  clientId: string;
  clientName: string;
  clientUri: string | undefined;
  redirectUri: string;
  scopes: string[];
  resource: string;
  registration: "cimd" | "dcr";
  requirePassword: boolean;
  passwordError?: boolean;
}

/**
 * The consent screen. Per the CIMD draft (section 6.4) and the MCP security
 * considerations it shows the client_id hostname, the redirect URI hostname,
 * and a warning for loopback redirect URIs. `logo_uri` is deliberately not
 * rendered: the draft asks servers to prefetch and moderate logos first.
 */
export function renderConsent(view: ConsentView): string {
  const clientUrl = new URL(view.clientId);
  const redirectUrl = new URL(view.redirectUri);
  const redirectIsLoopback = isLoopbackHostname(redirectUrl.hostname);
  const scopes = view.scopes.length ? view.scopes.map((s) => `<code>${escapeHtml(s)}</code>`).join(" ") : "<em>none</em>";
  const body = `
<h1>Allow <strong>${escapeHtml(view.clientName)}</strong> to use this MCP server?</h1>
<div class="card">
  <dl>
    <dt>Client</dt><dd>${escapeHtml(view.clientName)}${view.clientUri ? ` (<code>${escapeHtml(view.clientUri)}</code>)` : ""}</dd>
    <dt>Identified by</dt><dd><span class="host">${escapeHtml(clientUrl.host)}</span><br><code>${escapeHtml(view.clientId)}</code>${
      view.registration === "cimd" ? "" : "<br><small>Registered through deprecated Dynamic Client Registration</small>"
    }</dd>
    <dt>Will return to</dt><dd><span class="host">${escapeHtml(redirectUrl.host)}</span><br><code>${escapeHtml(view.redirectUri)}</code></dd>
    <dt>Permissions</dt><dd>${scopes}</dd>
    <dt>For resource</dt><dd><code>${escapeHtml(view.resource)}</code></dd>
  </dl>
  ${
    redirectIsLoopback
      ? `<div class="warn">This client runs on your own computer (<code>${escapeHtml(redirectUrl.host)}</code>). A Client ID Metadata Document cannot prove which local program will receive the authorization code. Only continue if you started this request yourself.</div>`
      : ""
  }
  ${view.passwordError ? `<div class="err">Incorrect password.</div>` : ""}
  <form method="post" action="/authorize/decision">
    <input type="hidden" name="request_id" value="${escapeHtml(view.requestId)}">
    ${
      view.requirePassword
        ? `<label>Consent password<input type="password" name="password" autocomplete="current-password" required></label>`
        : ""
    }
    <div class="actions">
      <button class="approve" name="decision" value="approve" type="submit">Approve</button>
      <button class="deny" name="decision" value="deny" type="submit">Deny</button>
    </div>
  </form>
</div>`;
  return page(`Authorize ${view.clientName}`, body);
}

export function renderError(title: string, description: string, details?: Record<string, string>): string {
  const rows = details
    ? `<dl>${Object.entries(details)
        .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd><code>${escapeHtml(v)}</code></dd>`)
        .join("")}</dl>`
    : "";
  return page(title, `<h1>${escapeHtml(title)}</h1><div class="card"><div class="err">${escapeHtml(description)}</div>${rows}</div>`);
}
