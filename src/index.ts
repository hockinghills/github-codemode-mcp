import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { createMcpHandler } from "agents/mcp";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";
import { createAuthHandlers } from "./auth/oauth-handler";
import { getGitHubUser } from "./auth/github-auth";
import { processGitHubSpec } from "./spec-processor";
import type { AuthProps } from "./auth/types";

const GIT_CREDENTIAL_TTL = 3600; // 1 hour sliding window

const GITHUB_SPEC_URL =
  "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";

let specCache: Record<string, unknown> | null = null;

async function getSpec(): Promise<Record<string, unknown>> {
  if (specCache) return specCache;
  const res = await fetch(GITHUB_SPEC_URL);
  if (!res.ok) throw new Error(`Failed to fetch GitHub OpenAPI spec: ${res.status}`);
  const raw = (await res.json()) as Record<string, unknown>;
  specCache = processGitHubSpec(raw);
  return specCache;
}

/**
 * Check if request has a direct GitHub PAT (not an OAuth-issued token)
 */
function isDirectToken(request: Request): boolean {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  // OAuth tokens from workers-oauth-provider have format userId:grantId:secret
  return !token.includes(":");
}

/**
 * Create MCP response for a given GitHub token
 */
async function createMcpResponse(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string,
  kv?: KVNamespace
): Promise<Response> {
  const spec = await getSpec();
  const executor = new DynamicWorkerExecutor({ loader: env.LOADER });

  const server = openApiMcpServer({
    spec,
    executor,
    name: "github",
    version: "1.0.0",
    description: `Execute JavaScript code against the GitHub REST API.

Available in your code:

interface RequestOptions {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  contentType?: string;
  rawBody?: boolean;
}

declare const codemode: {
  request(options: RequestOptions): Promise<unknown>;
};

The authenticated user's token is already included — do not pass auth headers.
The base URL (https://api.github.com) is prepended automatically — use paths like "/repos/owner/repo".

Example: List open pull requests for a repo:
async () => {
  return await codemode.request({
    method: "GET",
    path: "/repos/octocat/Hello-World/pulls",
    query: { state: "open", per_page: 10 }
  });
}

Example: Create an issue:
async () => {
  return await codemode.request({
    method: "POST",
    path: "/repos/octocat/Hello-World/issues",
    body: { title: "Bug report", body: "Something is broken" }
  });
}

Example: Search repositories:
async () => {
  return await codemode.request({
    method: "GET",
    path: "/search/repositories",
    query: { q: "language:typescript stars:>1000", sort: "stars", per_page: 5 }
  });
}`,
    request: async (opts) => {
      const url = new URL(`https://api.github.com${opts.path}`);
      if (opts.query) {
        for (const [key, value] of Object.entries(opts.query)) {
          if (value !== undefined) url.searchParams.set(key, String(value));
        }
      }

      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "github-codemode-mcp/1.0.0",
      };

      if (opts.contentType) {
        headers["Content-Type"] = opts.contentType;
      } else if (opts.body) {
        headers["Content-Type"] = "application/json";
      }

      const res = await fetch(url.toString(), {
        method: opts.method,
        headers,
        body: opts.body
          ? opts.rawBody
            ? (opts.body as string)
            : JSON.stringify(opts.body)
          : undefined,
      });

      const rateLimitRemaining = res.headers.get("x-ratelimit-remaining");
      const rateLimitReset = res.headers.get("x-ratelimit-reset");
      const contentType = res.headers.get("content-type") || "";
      const data = contentType.includes("application/json")
        ? await res.json().catch(() => null)
        : await res.text();

      if (!res.ok) {
        return {
          error: true,
          status: res.status,
          message:
            (typeof data === "object" && data !== null
              ? (data as Record<string, unknown>)?.message
              : undefined) ??
            (typeof data === "string" && data.length > 0 ? data : res.statusText),
          rateLimit: {
            remaining: rateLimitRemaining,
            resetsAt: rateLimitReset
              ? new Date(Number(rateLimitReset) * 1000).toISOString()
              : null,
          },
        };
      }

      return data;
    },
  });

  // Add setup_git_auth tool if KV is available
  if (kv) {
    server.tool(
      "setup_git_auth",
      "Configure git credentials for this session. Call once per session — git push/pull/clone will work for 1 hour of activity (sliding window, resets on each use). No parameters needed.",
      {},
      async () => {
        const user = await getGitHubUser(token);
        const key = crypto.randomUUID();
        const workerUrl = new URL(request.url).origin;

        // Fetch email if not on profile
        let email = user.email;
        if (!email) {
          const emailRes = await fetch("https://api.github.com/user/emails", {
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "User-Agent": "github-codemode-mcp/1.0.0",
            },
          });
          if (emailRes.ok) {
            const emails = (await emailRes.json()) as Array<{
              email: string;
              primary: boolean;
            }>;
            email = emails.find((e) => e.primary)?.email || emails[0]?.email;
          }
        }

        await kv.put(
          `git:cred:${key}`,
          JSON.stringify({ token, login: user.login, email: email || `${user.login}@users.noreply.github.com` }),
          { expirationTtl: GIT_CREDENTIAL_TTL }
        );

        const script = [
          "#!/bin/bash",
          `# Git credential helper — token never appears in this script`,
          `cat > /tmp/git-cred-helper.sh << 'HELPER'`,
          `#!/bin/bash`,
          `if [ "$1" = "get" ]; then`,
          `  curl -sf "${workerUrl}/credential/${key}"`,
          `fi`,
          `HELPER`,
          `chmod +x /tmp/git-cred-helper.sh`,
          `git config --global credential.helper '/tmp/git-cred-helper.sh'`,
          `git config --global user.name "${user.login}"`,
          `git config --global user.email "${email || `${user.login}@users.noreply.github.com`}"`,
          `echo "git auth configured for ${user.login}"`,
        ].join("\n");

        return {
          content: [
            {
              type: "text" as const,
              text: `Run this script to configure git credentials:\n\n\`\`\`bash\n${script}\n\`\`\`\n\nCredentials are valid for 1 hour of inactivity (each git operation resets the timer). If git auth expires, call setup_git_auth again.`,
            },
          ],
        };
      }
    );
  }

  return createMcpHandler(server)(request, env, ctx);
}

/**
 * MCP API handler — receives authenticated requests from OAuthProvider
 */
function createMcpApiHandler() {
  const app = new Hono();

  app.post("/mcp", async (c) => {
    const ctx = c.executionCtx as ExecutionContext & { props?: AuthProps };
    const props = ctx.props;
    if (!props?.accessToken) {
      return new Response(JSON.stringify({ error: "Not authenticated" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }
    return createMcpResponse(c.req.raw, c.env as Env, ctx, props.accessToken, (c.env as Env).OAUTH_KV);
  });

  return app;
}

/**
 * Handle git credential requests — returns credentials and resets TTL
 */
async function handleCredentialRequest(key: string, kv: KVNamespace): Promise<Response> {
  const stored = await kv.get(`git:cred:${key}`);
  if (!stored) {
    return new Response("not found", { status: 404 });
  }

  const { token, login, email } = JSON.parse(stored) as {
    token: string;
    login: string;
    email: string;
  };

  // Reset TTL — sliding window
  await kv.put(`git:cred:${key}`, stored, { expirationTtl: GIT_CREDENTIAL_TTL });

  // Git credential protocol format
  const body = [
    "protocol=https",
    "host=github.com",
    `username=${login}`,
    `password=${token}`,
    "",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Credential endpoint — no auth required, key is the secret
    if (url.pathname.startsWith("/credential/")) {
      const key = url.pathname.slice("/credential/".length);
      if (!key) {
        return new Response("missing key", { status: 400 });
      }
      return handleCredentialRequest(key, env.OAUTH_KV);
    }

    // Direct PAT mode — for CLI usage without OAuth
    if (isDirectToken(request)) {
      const token = request.headers.get("Authorization")!.slice(7);
      try {
        await getGitHubUser(token); // validate token
        return createMcpResponse(request, env, ctx, token, env.OAUTH_KV);
      } catch {
        return new Response(JSON.stringify({ error: "Invalid GitHub token" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // OAuth mode — for browser/claude.ai
    return new OAuthProvider({
      apiHandlers: {
        "/mcp": createMcpApiHandler(),
      },
      defaultHandler: createAuthHandlers(env as any),
      authorizeEndpoint: "/authorize",
      tokenEndpoint: "/token",
      clientRegistrationEndpoint: "/register",
      accessTokenTTL: 3600,
      refreshTokenTTL: 2592000,
      resourceMetadata: {
        resource_name: "GitHub API MCP Server",
      },
    }).fetch(request, env, ctx);
  },
};
