import { Hono } from "hono";
import { getGitHubToken, getGitHubUser } from "./github-auth";
import type { AuthProps } from "./types";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";

const CSRF_COOKIE = "__Host-CSRF_TOKEN";
const STATE_COOKIE = "__Host-CONSENTED_STATE";
const APPROVED_COOKIE = "__Host-MCP_APPROVED_CLIENTS";

// GitHub OAuth scopes
const DEFAULT_SCOPES = ["repo", "read:user", "user:email", "read:org", "workflow"];

/**
 * Sanitize text for HTML output
 */
function sanitize(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Generate CSRF token + cookie
 */
function generateCSRF(): { token: string; setCookie: string } {
  const token = crypto.randomUUID();
  return {
    token,
    setCookie: `${CSRF_COOKIE}=${token}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600`,
  };
}

/**
 * Validate CSRF token from form against cookie
 */
function validateCSRF(formToken: string, request: Request): void {
  const cookies = (request.headers.get("Cookie") || "").split(";").map((c) => c.trim());
  const csrfCookie = cookies.find((c) => c.startsWith(`${CSRF_COOKIE}=`));
  const cookieToken = csrfCookie?.substring(CSRF_COOKIE.length + 1);

  if (!formToken || !cookieToken || formToken !== cookieToken) {
    throw new Error("CSRF token mismatch");
  }
}

/**
 * Store OAuth state in KV, return state token
 */
async function createState(
  oauthReqInfo: AuthRequest,
  kv: KVNamespace
): Promise<string> {
  const stateToken = crypto.randomUUID();
  await kv.put(`oauth:state:${stateToken}`, JSON.stringify(oauthReqInfo), {
    expirationTtl: 600,
  });
  return stateToken;
}

/**
 * Bind state to session via hashed cookie
 */
async function bindSession(stateToken: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(stateToken)
  );
  const hex = Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${STATE_COOKIE}=${hex}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600`;
}

/**
 * Validate state from callback against KV + session cookie
 */
async function validateState(
  stateToken: string,
  request: Request,
  kv: KVNamespace
): Promise<AuthRequest> {
  const stored = await kv.get(`oauth:state:${stateToken}`);
  if (!stored) throw new Error("Invalid or expired state");

  // Verify session binding
  const cookies = (request.headers.get("Cookie") || "").split(";").map((c) => c.trim());
  const stateCookie = cookies.find((c) => c.startsWith(`${STATE_COOKIE}=`));
  const cookieHash = stateCookie?.substring(STATE_COOKIE.length + 1);
  if (!cookieHash) throw new Error("Missing session binding");

  const expectedHash = Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stateToken))
    )
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (cookieHash !== expectedHash) throw new Error("State mismatch");

  await kv.delete(`oauth:state:${stateToken}`);
  return JSON.parse(stored) as AuthRequest;
}

/**
 * Render a simple consent dialog
 */
function renderConsent(
  clientName: string,
  csrfToken: string,
  stateJson: string,
  setCookie: string
): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize ${sanitize(clientName)} | GitHub MCP</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; max-width: 420px; width: 100%; padding: 2rem; }
    .logo { text-align: center; margin-bottom: 1.5rem; }
    .logo svg { width: 48px; height: 48px; fill: #e6edf3; }
    h1 { font-size: 1.25rem; text-align: center; margin-bottom: 0.5rem; }
    .sub { text-align: center; color: #8b949e; font-size: 0.9rem; margin-bottom: 1.5rem; }
    .client { background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1.5rem; text-align: center; font-weight: 500; }
    .scopes { background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }
    .scopes h3 { font-size: 0.75rem; text-transform: uppercase; color: #8b949e; margin-bottom: 0.5rem; }
    .scope { font-family: monospace; font-size: 0.85rem; color: #79c0ff; padding: 0.25rem 0; }
    .actions { display: flex; gap: 0.75rem; }
    .btn { flex: 1; padding: 0.75rem; border-radius: 8px; border: none; font-size: 0.9rem; font-weight: 500; cursor: pointer; font-family: inherit; }
    .btn-primary { background: #238636; color: white; }
    .btn-primary:hover { background: #2ea043; }
    .btn-secondary { background: transparent; border: 1px solid #30363d; color: #e6edf3; }
    .btn-secondary:hover { background: #21262d; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
    </div>
    <h1>Authorize Application</h1>
    <p class="sub">Grant access to the GitHub API via MCP</p>
    <div class="client">${sanitize(clientName)}</div>
    <div class="scopes">
      <h3>Permissions requested</h3>
      ${DEFAULT_SCOPES.map((s) => `<div class="scope">${sanitize(s)}</div>`).join("")}
    </div>
    <form method="post">
      <input type="hidden" name="state" value="${sanitize(stateJson)}">
      <input type="hidden" name="csrf_token" value="${sanitize(csrfToken)}">
      <div class="actions">
        <button type="button" class="btn btn-secondary" onclick="window.close()">Cancel</button>
        <button type="submit" class="btn btn-primary">Authorize</button>
      </div>
    </form>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
      "Set-Cookie": setCookie,
    },
  });
}

/**
 * Render error page
 */
function renderError(title: string, message: string, status = 400): Response {
  const html = `<!DOCTYPE html>
<html><head><title>${sanitize(title)}</title>
<style>body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;max-width:400px;text-align:center}h1{color:#f85149;margin-bottom:1rem}p{color:#8b949e}</style></head>
<body><div class="card"><h1>${sanitize(title)}</h1><p>${sanitize(message)}</p></div></body></html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/**
 * Create the OAuth auth handler routes
 */
export function createAuthHandlers(env: {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  MCP_COOKIE_ENCRYPTION_KEY: string;
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
}) {
  const app = new Hono();

  // GET /authorize — show consent dialog
  app.get("/authorize", async (c) => {
    try {
      const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
      if (!oauthReqInfo.clientId) {
        return renderError("Invalid Request", "Missing client_id");
      }

      const { token: csrfToken, setCookie } = generateCSRF();
      const stateJson = btoa(JSON.stringify({ oauthReqInfo }));
      const clientName = (
        await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId)
      )?.clientName || "MCP Client";

      return renderConsent(clientName, csrfToken, stateJson, setCookie);
    } catch (e) {
      console.error("Authorize error:", e);
      return renderError("Error", "Failed to process authorization request", 500);
    }
  });

  // POST /authorize — user approved, redirect to GitHub
  app.post("/authorize", async (c) => {
    try {
      const formData = await c.req.raw.formData();
      const csrfToken = formData.get("csrf_token") as string;
      validateCSRF(csrfToken, c.req.raw);

      const stateStr = formData.get("state") as string;
      const { oauthReqInfo } = JSON.parse(atob(stateStr));

      // Store state in KV
      const stateToken = await createState(oauthReqInfo, env.OAUTH_KV);
      const sessionCookie = await bindSession(stateToken);

      // Build GitHub authorize URL
      const params = new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        redirect_uri: new URL("/oauth/callback", c.req.url).href,
        scope: DEFAULT_SCOPES.join(" "),
        state: stateToken,
      });

      return new Response(null, {
        status: 302,
        headers: {
          Location: `https://github.com/login/oauth/authorize?${params}`,
          "Set-Cookie": sessionCookie,
        },
      });
    } catch (e) {
      console.error("Authorize POST error:", e);
      return renderError("Error", String(e), 400);
    }
  });

  // GET /oauth/callback — GitHub redirects back here
  app.get("/oauth/callback", async (c) => {
    try {
      const code = c.req.query("code");
      const stateToken = c.req.query("state");
      if (!code || !stateToken) {
        return renderError("Invalid Request", "Missing code or state");
      }

      // Validate state
      const oauthReqInfo = await validateState(stateToken, c.req.raw, env.OAUTH_KV);

      // Exchange code for GitHub token
      const { access_token } = await getGitHubToken({
        clientId: env.GITHUB_CLIENT_ID,
        clientSecret: env.GITHUB_CLIENT_SECRET,
        code,
        redirectUri: new URL("/oauth/callback", c.req.url).href,
      });

      // Fetch GitHub user
      const user = await getGitHubUser(access_token);

      // Ensure client is registered
      if (oauthReqInfo.clientId) {
        await env.OAUTH_PROVIDER.createClient({
          clientId: oauthReqInfo.clientId,
          tokenEndpointAuthMethod: "none",
        });
      }

      // Complete the MCP OAuth flow
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: oauthReqInfo,
        userId: String(user.id),
        metadata: { label: user.login },
        scope: oauthReqInfo.scope,
        props: {
          accessToken: access_token,
          user,
        } satisfies AuthProps,
      });

      const clearCookie = `${STATE_COOKIE}=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`;

      return new Response(null, {
        status: 302,
        headers: {
          Location: redirectTo,
          "Set-Cookie": clearCookie,
        },
      });
    } catch (e) {
      console.error("Callback error:", e);
      return renderError("Authorization Failed", String(e), 500);
    }
  });

  return app;
}
