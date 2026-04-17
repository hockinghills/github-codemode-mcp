import { createMcpHandler } from "agents/mcp";
import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { openApiMcpServer } from "@cloudflare/codemode/mcp";

const GITHUB_SPEC_URL =
  "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";

let specCache: Record<string, unknown> | null = null;

async function getSpec(): Promise<Record<string, unknown>> {
  if (specCache) return specCache;
  const res = await fetch(GITHUB_SPEC_URL);
  if (!res.ok) {
    throw new Error(`Failed to fetch GitHub OpenAPI spec: ${res.status}`);
  }
  specCache = (await res.json()) as Record<string, unknown>;
  return specCache;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    // Extract auth token from the incoming request
    const authHeader = request.headers.get("Authorization");
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return new Response(
        JSON.stringify({
          error:
            "Authorization header with Bearer token required. Use a GitHub personal access token.",
        }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

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
            if (value !== undefined) {
              url.searchParams.set(key, String(value));
            }
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

        // Return response with rate limit info
        const rateLimitRemaining = res.headers.get("x-ratelimit-remaining");
        const rateLimitReset = res.headers.get("x-ratelimit-reset");

        const data = await res.json().catch(() => null);

        if (!res.ok) {
          return {
            error: true,
            status: res.status,
            message: (data as Record<string, unknown>)?.message ?? res.statusText,
            documentation_url:
              (data as Record<string, unknown>)?.documentation_url,
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

    return createMcpHandler(server)(request, env, ctx);
  },
};
