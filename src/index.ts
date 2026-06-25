#!/usr/bin/env node
/**
 * @ledgerproof/mcp-server — entry point.
 *
 * Two CURRENT MCP transports (no deprecated SSE transport):
 *   - stdio (default): `npx @ledgerproof/mcp-server`
 *   - Streamable HTTP: `npx @ledgerproof/mcp-server --http [--port N] [--host H]`
 *
 * Configuration comes from environment variables (see config.ts / README).
 * The signing key is never logged.
 */

import { randomUUID } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

import { loadConfig, type ResolvedConfig, type SafeConfigSummary } from "./config.js";
import { createServer } from "./server.js";

/**
 * A boot-log label for the Transparency-Service key. The TS key is PUBLIC, so
 * we log its source and short fingerprint — never any private key material.
 *   - "env:<fp>"        key supplied via LEDGERPROOF_TS_PUBLIC_KEY_HEX
 *   - "endpoint(lazy)"  will be fetched from {apiBase}/v1/scitt/ts-key on demand
 *   - "none"            no TS key configured (receipt sig can't be confirmed)
 */
function tsKeyBootLabel(summary: SafeConfigSummary): string {
  if (summary.tsPublicKeySource === "env") {
    return `env:${summary.tsPublicKeyFingerprint ?? "?"}`;
  }
  if (summary.tsPublicKeySource === "endpoint") return "endpoint(lazy)";
  return "none";
}

interface CliOptions {
  http: boolean;
  port: number;
  host: string;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    http:
      argv.includes("--http") ||
      process.env.LEDGERPROOF_MCP_TRANSPORT?.toLowerCase() === "http",
    port: Number(process.env.PORT ?? process.env.LEDGERPROOF_MCP_PORT ?? 3000),
    host: process.env.LEDGERPROOF_MCP_HOST ?? "127.0.0.1",
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--port" && argv[i + 1]) opts.port = Number(argv[++i]);
    else if (argv[i] === "--host" && argv[i + 1]) opts.host = String(argv[++i]);
  }
  return opts;
}

/** Read the full request body as a Buffer, then JSON-parse (tolerant of empty). */
function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(undefined);
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

async function runStdio(config: ResolvedConfig): Promise<void> {
  // stdio is local: allow raw artifacts (still hashed locally by the SDK).
  const server = createServer({
    client: config.client,
    summary: config.summary,
    remote: false,
    getTsPublicKey: config.getTsPublicKey,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // IMPORTANT: never write protocol noise to stdout on stdio. Logs go to stderr.
  console.error(
    `[ledgerproof-mcp] stdio transport ready · publisher=${config.summary.publisherId} ` +
      `country=${config.summary.deployerCountry} api=${config.summary.apiBase} ` +
      `signingKey=${config.summary.hasSigningKey ? "provided" : "ephemeral"} ` +
      `tsKey=${tsKeyBootLabel(config.summary)}`
  );
}

async function runHttp(config: ResolvedConfig, opts: CliOptions): Promise<void> {
  // One transport+server per session, keyed by the MCP session id header.
  const sessions = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createHttpServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      try {
        if (!req.url) {
          res.writeHead(400).end("missing url");
          return;
        }
        const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
        if (url.pathname !== "/mcp") {
          res.writeHead(404, { "content-type": "application/json" }).end(
            JSON.stringify({ error: "not found", hint: "POST/GET/DELETE /mcp" })
          );
          return;
        }

        const sessionId = req.headers["mcp-session-id"] as string | undefined;

        // Existing session → reuse its transport.
        if (sessionId && sessions.has(sessionId)) {
          const transport = sessions.get(sessionId)!;
          const body = req.method === "POST" ? await readBody(req) : undefined;
          await transport.handleRequest(req, res, body);
          return;
        }

        // New session: must be an initialize POST.
        if (req.method === "POST") {
          const body = await readBody(req);
          if (!isInitializeRequest(body)) {
            res.writeHead(400, { "content-type": "application/json" }).end(
              JSON.stringify({
                jsonrpc: "2.0",
                error: {
                  code: -32000,
                  message:
                    "Bad Request: no valid session id, and not an initialize request.",
                },
                id: null,
              })
            );
            return;
          }

          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sid: string) => {
              sessions.set(sid, transport);
              console.error(`[ledgerproof-mcp] http session opened: ${sid}`);
            },
          });
          transport.onclose = () => {
            if (transport.sessionId) {
              sessions.delete(transport.sessionId);
              console.error(
                `[ledgerproof-mcp] http session closed: ${transport.sessionId}`
              );
            }
          };

          // remote=true → issue_receipt requires precomputed_sha256.
          const server = createServer({
            client: config.client,
            summary: config.summary,
            remote: true,
            getTsPublicKey: config.getTsPublicKey,
          });
          await server.connect(transport);
          await transport.handleRequest(req, res, body);
          return;
        }

        // GET/DELETE without a known session id → invalid.
        res.writeHead(400, { "content-type": "application/json" }).end(
          JSON.stringify({ error: "missing or unknown mcp-session-id" })
        );
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        console.error(`[ledgerproof-mcp] http error: ${reason}`);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json" }).end(
            JSON.stringify({ error: "internal error" })
          );
        }
      }
    }
  );

  httpServer.listen(opts.port, opts.host, () => {
    console.error(
      `[ledgerproof-mcp] Streamable HTTP transport ready on ` +
        `http://${opts.host}:${opts.port}/mcp · publisher=${config.summary.publisherId} ` +
        `country=${config.summary.deployerCountry} api=${config.summary.apiBase} ` +
        `signingKey=${config.summary.hasSigningKey ? "provided" : "ephemeral"} ` +
        `tsKey=${tsKeyBootLabel(config.summary)} ` +
        `(remote mode: issue_receipt requires precomputed_sha256)`
    );
  });
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  let config: ResolvedConfig;
  try {
    config = loadConfig();
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.error(`[ledgerproof-mcp] configuration error: ${reason}`);
    process.exit(1);
  }

  if (opts.http) {
    await runHttp(config, opts);
  } else {
    await runStdio(config);
  }
}

main().catch((err) => {
  const reason = err instanceof Error ? err.message : String(err);
  console.error(`[ledgerproof-mcp] fatal: ${reason}`);
  process.exit(1);
});
