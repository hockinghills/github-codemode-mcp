# github-codemode-mcp

A GitHub API MCP server built on [Cloudflare Code Mode](https://developers.cloudflare.com/agents/guides/remote-mcp-server/). Instead of exposing individual tools for each GitHub API endpoint, it provides two tools — `search` and `execute` — that let the AI write and run JavaScript directly against GitHub's REST API.

## How it works

- **`search`** — Searches the GitHub OpenAPI spec. The AI writes JavaScript to query the spec object and find endpoints, parameters, and schemas.
- **`execute`** — Executes JavaScript code against the GitHub API. The AI writes an async arrow function using `codemode.request()` to call any GitHub endpoint.

The full GitHub OpenAPI spec is fetched, processed (refs resolved, simplified for LLM consumption), and cached. The AI gets the spec to search through and a `codemode.request()` function that handles auth, base URL, and headers automatically.

## Authentication

Supports two modes:

- **OAuth** (browser/Claude.ai) — Full OAuth flow via `@cloudflare/workers-oauth-provider`. Users authorize through GitHub and the server manages token lifecycle.
- **Direct PAT** (CLI) — Pass a GitHub Personal Access Token as a Bearer token. No OAuth dance needed.

## OAuth scopes

`repo`, `read:user`, `user:email`, `read:org`, `workflow`

## Setup

```bash
npm install
```

### Development

```bash
npm run dev
```

### Deploy

```bash
npm run deploy
```

## Configuration

Requires a Cloudflare Workers KV namespace for OAuth state management. See `wrangler.jsonc` for the binding configuration.

Environment variables needed:
- `GITHUB_CLIENT_ID` — GitHub OAuth App client ID
- `GITHUB_CLIENT_SECRET` — GitHub OAuth App client secret

## Stack

- [Cloudflare Workers](https://workers.cloudflare.com/)
- [@cloudflare/codemode](https://www.npmjs.com/package/@cloudflare/codemode)
- [@cloudflare/workers-oauth-provider](https://www.npmjs.com/package/@cloudflare/workers-oauth-provider)
- [Hono](https://hono.dev/) — routing
- [Zod](https://zod.dev/) — validation
