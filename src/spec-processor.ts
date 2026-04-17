const HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"] as const;

interface RawParam {
  name?: string;
  in?: string;
  required?: boolean;
  description?: string;
  schema?: { type?: string; enum?: string[] };
}

interface RawOperation {
  summary?: string;
  description?: string;
  tags?: string[];
  operationId?: string;
  parameters?: (RawParam | { $ref?: string })[];
  requestBody?: {
    description?: string;
    required?: boolean;
    content?: Record<string, { schema?: unknown }>;
  };
  responses?: Record<string, { description?: string }>;
}

/**
 * Resolve a single $ref pointer against the spec root.
 * Returns the resolved object or undefined.
 */
function resolveRef(ref: string, root: Record<string, unknown>): unknown {
  if (!ref.startsWith("#/")) return undefined;
  const parts = ref.slice(2).split("/");
  let current: unknown = root;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/**
 * Simplify a parameter to just what the LLM needs: name, location, type, required.
 */
function simplifyParam(
  param: RawParam | { $ref?: string },
  root: Record<string, unknown>
): { name: string; in: string; required?: boolean; type?: string; description?: string } | null {
  let resolved = param as RawParam;
  if ("$ref" in param && typeof param.$ref === "string") {
    resolved = resolveRef(param.$ref, root) as RawParam;
    if (!resolved) return null;
  }
  return {
    name: resolved.name || "unknown",
    in: resolved.in || "query",
    required: resolved.required,
    type: resolved.schema?.type,
    description: resolved.description,
  };
}

/**
 * Process the raw GitHub OpenAPI spec into a compact format.
 * Strips full JSON schemas, response bodies, and components.
 * Keeps only what the LLM needs to discover and call endpoints.
 */
export function processGitHubSpec(raw: Record<string, unknown>): Record<string, unknown> {
  const rawPaths = (raw.paths || {}) as Record<string, Record<string, RawOperation>>;
  const paths: Record<string, Record<string, unknown>> = {};

  for (const [path, pathItem] of Object.entries(rawPaths)) {
    if (!pathItem) continue;
    paths[path] = {};

    // Collect path-level parameters
    const pathParams = ((pathItem as Record<string, unknown>).parameters as RawParam[]) || [];

    for (const method of HTTP_METHODS) {
      const op = pathItem[method];
      if (!op) continue;

      // Merge path-level + operation-level parameters with operation-level override
      const paramMap = new Map<
        string,
        { name: string; in: string; required?: boolean; type?: string; description?: string }
      >();
      for (const p of [...pathParams, ...(op.parameters || [])]) {
        const simplified = simplifyParam(p, raw);
        if (!simplified) continue;
        paramMap.set(`${simplified.in}:${simplified.name}`, simplified);
      }
      const params = [...paramMap.values()];

      // Simplify request body to just description + required
      let requestBody: { description?: string; required?: boolean; contentType?: string } | undefined;
      if (op.requestBody) {
        const contentTypes = op.requestBody.content ? Object.keys(op.requestBody.content) : [];
        requestBody = {
          description: op.requestBody.description,
          required: op.requestBody.required,
          contentType: contentTypes[0],
        };
      }

      // Simplify responses to just status code + description
      const responses: Record<string, string> = {};
      if (op.responses) {
        for (const [status, resp] of Object.entries(op.responses)) {
          responses[status] = (resp as Record<string, string>)?.description || status;
        }
      }

      paths[path][method] = {
        summary: op.summary,
        description: op.description,
        tags: op.tags,
        operationId: op.operationId,
        parameters: params.length > 0 ? params : undefined,
        requestBody,
        responses,
      };
    }
  }

  return {
    openapi: raw.openapi,
    info: raw.info,
    paths,
    servers: raw.servers,
    tags: raw.tags,
    // No components — everything is inlined and simplified
  };
}
