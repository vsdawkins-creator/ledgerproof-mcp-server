/**
 * LedgerProof MCP server definition.
 *
 * Builds an McpServer exposing four tools and one prompt over the @ledgerproof/sdk.
 * A fresh server is created per transport so the `remote` flag (true for
 * Streamable HTTP) can tighten the issue-receipt privacy rules.
 *
 * Honest positioning (see SCITT profile §0): LedgerProof implements the IETF
 * SCITT architecture drafts with COSE Receipts, additionally anchored to
 * Bitcoin. It is NOT an RFC, standard, certified, or "compliant" profile.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  artifactHash,
  sha256Hex,
  type ContentCategory,
  type GenerationType,
  type PerceptualHash,
} from "@ledgerproof/sdk";
import type { LedgerProof } from "@ledgerproof/sdk";
import { z } from "zod";

import type { SafeConfigSummary } from "./config.js";
import {
  ScittUnavailableError,
  coerceTransparentStatement,
  verifyTransparentStatement,
} from "./scitt.js";

const SHA256_HEX = /^[0-9a-f]{64}$/i;

const CONTENT_CATEGORIES = [
  "SYNTHETIC_TEXT",
  "SYNTHETIC_IMAGE",
  "SYNTHETIC_AUDIO",
  "SYNTHETIC_VIDEO",
  "DEEPFAKE",
  "SYNTHETIC_MULTIMODAL",
  "AI_ASSISTED_DOCUMENT",
] as const;

const GENERATION_TYPES = [
  "FULLY_GENERATED",
  "AI_MANIPULATED",
  "AI_ASSISTED",
] as const;

export interface CreateServerOptions {
  client: LedgerProof;
  summary: SafeConfigSummary;
  /** True when served over Streamable HTTP (remote). Tightens privacy rules. */
  remote: boolean;
  /**
   * Lazily resolve the Transparency-Service PUBLIC key (32 bytes) used to verify
   * a Receipt's COSE_Sign1 signature (spec §7 step 4). Sourced from
   * LEDGERPROOF_TS_PUBLIC_KEY_HEX or fetched from {apiBase}/v1/scitt/ts-key.
   * Optional: when absent the verifier reports receiptSignatureValid:false
   * rather than trusting the API.
   */
  getTsPublicKey?: () => Promise<Uint8Array | undefined>;
}

/** Build a JSON tool result (text content carrying a pretty-printed object). */
function jsonResult(obj: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }],
  };
}

/** Build an error tool result with a clear, secret-free message. */
function errorResult(message: string) {
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: message }],
  };
}

/**
 * Extract a usable anchor status from a verifier EntryResponse. The public
 * verifier returns the chain entry; Bitcoin anchoring is asynchronous, so a
 * freshly issued entry is "pending" until the daily Merkle root is written to
 * an OP_RETURN. We surface whatever anchor fields the API exposes and never
 * fabricate an "anchored" status.
 */
function readAnchor(entry: Record<string, unknown> | null): {
  anchor_status: "anchored" | "pending" | "unknown";
  txid: string | null;
  block_height: number | null;
  block_hash: string | null;
  merkle_proof: unknown;
  anchored_at: string | null;
} {
  if (!entry) {
    return {
      anchor_status: "unknown",
      txid: null,
      block_height: null,
      block_hash: null,
      merkle_proof: null,
      anchored_at: null,
    };
  }
  const anchor =
    (entry["anchor"] as Record<string, unknown> | undefined) ?? entry;
  const txid =
    (anchor["txid"] as string | undefined) ??
    (anchor["bitcoin_txid"] as string | undefined) ??
    (entry["txid"] as string | undefined) ??
    null;
  const blockHeight =
    (anchor["block_height"] as number | undefined) ??
    (anchor["block"] as number | undefined) ??
    (entry["block_height"] as number | undefined) ??
    null;
  const blockHash =
    (anchor["block_hash"] as string | undefined) ??
    (entry["block_hash"] as string | undefined) ??
    null;
  const merkleProof =
    anchor["merkle_proof"] ??
    anchor["inclusion_proof"] ??
    entry["merkle_proof"] ??
    null;
  const anchoredAt =
    (anchor["anchored_at"] as string | undefined) ??
    (entry["anchored_at"] as string | undefined) ??
    null;

  // Honest rule: only call it "anchored" when there is a real Bitcoin txid.
  const anchored = typeof txid === "string" && txid.length > 0;
  return {
    anchor_status: anchored ? "anchored" : "pending",
    txid,
    block_height: blockHeight,
    block_hash: blockHash,
    merkle_proof: merkleProof,
    anchored_at: anchoredAt,
  };
}

/**
 * Publish an Article-50 record from a precomputed SHA-256 without the raw
 * artifact bytes, via the SDK's `precomputedArtifactHash` entrypoint. The SDK
 * skips local hashing and sets content.artifact_hash to the supplied digest,
 * then canonicalizes + Ed25519-signs + publishes exactly as the raw path does.
 *
 * The option set is cast through `unknown` because an installed SDK *build*
 * whose dist predates this entrypoint won't have `precomputedArtifactHash` in
 * its published types yet; the field is honored at runtime once the SDK that
 * supports it is in place. If the running SDK truly lacks the entrypoint it
 * raises a ValidationError ("requires either `artifact` … or
 * `precomputedArtifactHash`"), which we surface verbatim.
 */
async function publishPrecomputed(
  client: LedgerProof,
  base: Record<string, unknown>,
  precomputedSha256: string,
  artifactBytes: number | undefined,
  artifactContentType: string
): Promise<unknown> {
  const opts = {
    ...base,
    artifactContentType,
    precomputedArtifactHash: precomputedSha256,
    artifactBytes,
  };
  try {
    return await client.publishAiArticle50(
      opts as unknown as Parameters<LedgerProof["publishAiArticle50"]>[0]
    );
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(
      "Failed to issue from a precomputed SHA-256. The installed " +
        "@ledgerproof/sdk build may predate the precomputed-hash entrypoint " +
        "(publishAiArticle50 with `precomputedArtifactHash`); rebuild/upgrade " +
        "the SDK, or run over stdio and pass the raw `artifact` (still hashed " +
        `locally — only the hash reaches the API). Underlying error: ${reason}`
    );
  }
}

export function createServer(opts: CreateServerOptions): McpServer {
  const { client, summary, remote, getTsPublicKey } = opts;

  /** Decode a 64-hex-char Ed25519 public key to 32 bytes (issuer override). */
  function pubKeyHexToBytes(hex: string): Uint8Array {
    const clean = hex.trim();
    if (!/^[0-9a-f]{64}$/i.test(clean)) {
      throw new Error("public key must be 64 hex characters (32 bytes)");
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  /**
   * Look up the Bitcoin anchor txid for a daily root via the public SCITT
   * endpoints, when the caller didn't embed it in the Transparent Statement.
   * Best-effort: tries a couple of conventional shapes and returns undefined on
   * any miss so verification still reports steps 1-4 honestly.
   */
  async function lookupAnchorTxid(rootHex: string): Promise<string | undefined> {
    if (!rootHex) return undefined;
    const base = summary.apiBase.replace(/\/$/, "");
    const urls = [
      `${base}/v1/scitt/anchor?root=${encodeURIComponent(rootHex)}`,
      `${base}/v1/scitt/anchor/${encodeURIComponent(rootHex)}`,
    ];
    for (const url of urls) {
      try {
        const resp = await fetch(url);
        if (!resp.ok) continue;
        const body = (await resp.json()) as Record<string, unknown>;
        const txid =
          (body["txid"] as string | undefined) ??
          (body["bitcoin_txid"] as string | undefined) ??
          (typeof body["anchor"] === "object" && body["anchor"]
            ? ((body["anchor"] as Record<string, unknown>)["txid"] as
                | string
                | undefined)
            : undefined);
        if (typeof txid === "string" && txid.length > 0) return txid;
      } catch {
        // try the next shape
      }
    }
    return undefined;
  }

  const server = new McpServer(
    {
      name: "@ledgerproof/mcp-server",
      version: "0.1.0",
    },
    {
      instructions:
        "LedgerProof issues and verifies EU AI Act Article 50 transparency " +
        "receipts for AI-generated content. It implements the IETF SCITT " +
        "architecture drafts with COSE Receipts and additionally anchors a " +
        "daily Merkle root to Bitcoin. It is not an RFC, standard, or " +
        "certified profile. Issuing a receipt is a real action that ultimately " +
        "costs a Bitcoin transaction fee to anchor; do not issue receipts on " +
        "loose or speculative triggers. Read the `ledgerproof_when_to_issue` " +
        "prompt first. Anchoring is asynchronous: issuance returns " +
        "anchor_status 'pending'; poll ledgerproof_check_anchor until 'anchored'." +
        (remote
          ? " This server is reachable over Streamable HTTP (remote): " +
            "ledgerproof_issue_receipt requires precomputed_sha256 and rejects " +
            "raw payloads so artifact bytes never cross the network."
          : ""),
    }
  );

  // ── Tool 1: issue a receipt ────────────────────────────────────────────
  server.registerTool(
    "ledgerproof_issue_receipt",
    {
      title: "Issue an Article-50 transparency receipt",
      description:
        "Produce an EU AI Act Article 50 transparency record for a piece of " +
        "AI-generated content and register it with LedgerProof. Provide " +
        "EXACTLY ONE of `artifact` (the raw content; hashed locally, never " +
        "uploaded) or `precomputed_sha256` (a SHA-256 hex you computed " +
        "yourself), plus the AI-system and deployer metadata. Mirrors the " +
        "SDK's publishAiArticle50. Returns {sequence, entry_hash, verify_url, " +
        "anchor_status}. anchor_status is ALWAYS 'pending' on issuance because " +
        "Bitcoin anchoring is asynchronous (a daily Merkle root is written to " +
        "an OP_RETURN, which costs a Bitcoin tx fee) — poll " +
        "ledgerproof_check_anchor until it becomes 'anchored'. Do not issue on " +
        "loose triggers." +
        (remote
          ? " NOTE: over Streamable HTTP this tool REQUIRES precomputed_sha256 " +
            "and rejects raw `artifact` so payloads never leave your machine."
          : ""),
      inputSchema: {
        artifact: z
          .string()
          .optional()
          .describe(
            "Raw AI-generated content (text). Hashed locally with SHA-256; " +
              "the bytes are never sent to the LedgerProof API. Mutually " +
              "exclusive with precomputed_sha256. Rejected over Streamable HTTP."
          ),
        precomputed_sha256: z
          .string()
          .regex(SHA256_HEX, "must be 64 lowercase/uppercase hex characters")
          .optional()
          .describe(
            "SHA-256 (hex) of the artifact, computed by the caller (e.g. via " +
              "ledgerproof_hash_artifact). Keeps raw payloads off the wire. " +
              "Mutually exclusive with artifact. Required over Streamable HTTP."
          ),
        artifact_content_type: z
          .string()
          .default("text/plain")
          .describe("MIME type of the artifact, e.g. text/plain, image/png."),
        artifact_bytes: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .describe(
            "Byte length of the artifact. Used with precomputed_sha256 since " +
              "the raw bytes are unavailable to the server."
          ),
        aiSystemId: z
          .string()
          .describe("Identifier of the AI system, e.g. 'openai/gpt-4o'."),
        deployerName: z
          .string()
          .describe(
            "Legal name of the deployer organization (not an email/person)."
          ),
        contentCategory: z
          .enum(CONTENT_CATEGORIES)
          .describe("Article-50 content category."),
        aiSystemVersion: z
          .string()
          .optional()
          .describe("Version of the AI system, if known."),
        supervisoryAuthority: z
          .string()
          .optional()
          .describe("Relevant supervisory authority, if applicable."),
        generationType: z
          .enum(GENERATION_TYPES)
          .optional()
          .describe("How the content was produced."),
        sourceContentHash: z
          .string()
          .optional()
          .describe("SHA-256 of source content for manipulated/assisted media."),
        perceptualHash: z
          .object({
            algorithm: z.string(),
            value: z.string(),
            bits: z.number().int(),
          })
          .optional()
          .describe("Perceptual hash (algorithm, value, bits) for media."),
        transparencyMarker: z
          .string()
          .optional()
          .describe("Transparency marker label (defaults to LPR-EU-AI-ACT-50)."),
        isPublicInterest: z
          .boolean()
          .optional()
          .describe("Whether the content is in the public interest."),
        enforcementDate: z
          .string()
          .optional()
          .describe("Article-50 enforcement date (defaults to 2026-08-02)."),
        profileVersion: z
          .string()
          .optional()
          .describe("LPR profile version (defaults to EU-AI-ACT-50-v1.1)."),
      },
      annotations: {
        title: "Issue an Article-50 transparency receipt",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) => {
      const hasArtifact =
        typeof args.artifact === "string" && args.artifact.length > 0;
      const hasPrecomputed =
        typeof args.precomputed_sha256 === "string" &&
        args.precomputed_sha256.length > 0;

      if (hasArtifact === hasPrecomputed) {
        return errorResult(
          "Provide exactly one of `artifact` or `precomputed_sha256` (you " +
            (hasArtifact ? "provided both" : "provided neither") + ")."
        );
      }
      if (remote && hasArtifact) {
        return errorResult(
          "Over Streamable HTTP this server refuses raw `artifact` so payloads " +
            "never leave your machine. Hash it locally (ledgerproof_hash_artifact) " +
            "and pass `precomputed_sha256` instead."
        );
      }

      const baseMeta = {
        aiSystemId: args.aiSystemId,
        deployerName: args.deployerName,
        contentCategory: args.contentCategory as ContentCategory,
        aiSystemVersion: args.aiSystemVersion,
        supervisoryAuthority: args.supervisoryAuthority,
        generationType: args.generationType as GenerationType | undefined,
        sourceContentHash: args.sourceContentHash,
        perceptualHash: args.perceptualHash as PerceptualHash | undefined,
        transparencyMarker: args.transparencyMarker,
        isPublicInterest: args.isPublicInterest,
        enforcementDate: args.enforcementDate,
        profileVersion: args.profileVersion,
      };

      try {
        let receipt: {
          sequence: number;
          entry_hash: string;
          verify_url: string;
          receipt_id?: number;
        };

        if (hasArtifact) {
          receipt = (await client.publishAiArticle50({
            artifact: args.artifact as string,
            artifactContentType: args.artifact_content_type,
            ...baseMeta,
          })) as typeof receipt;
        } else {
          receipt = (await publishPrecomputed(
            client,
            baseMeta,
            args.precomputed_sha256 as string,
            args.artifact_bytes,
            args.artifact_content_type
          )) as typeof receipt;
        }

        return jsonResult({
          sequence: receipt.sequence,
          entry_hash: receipt.entry_hash,
          verify_url: receipt.verify_url,
          // Issuance is asynchronous — anchoring to Bitcoin has not happened yet.
          anchor_status: "pending",
          note: "Anchoring to Bitcoin is asynchronous. Poll ledgerproof_check_anchor with this sequence until anchor_status is 'anchored'.",
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        return errorResult(`Failed to issue receipt: ${reason}`);
      }
    }
  );

  // ── Tool 2: verify a receipt ───────────────────────────────────────────
  server.registerTool(
    "ledgerproof_verify_receipt",
    {
      title: "Verify a transparency receipt",
      description:
        "Verify a LedgerProof receipt. Provide EITHER {sequence} (looks up the " +
        "chain entry from the public verifier) OR {transparent_statement} (a " +
        "SCITT Transparent Statement bundle, verified with the trust-minimized " +
        "§7 algorithm: issuer COSE_Sign1 signature, RFC 9162 inclusion proof, " +
        "Transparency-Service receipt signature, and an independent Bitcoin " +
        "OP_RETURN check). For a Transparent Statement, returns " +
        "{issuerSignatureValid, inclusionProofValid, receiptSignatureValid, " +
        "bitcoinConfirmed, valid, recomputedRoot}. The Transparency-Service " +
        "PUBLIC key (for the receipt signature) is loaded from " +
        "LEDGERPROOF_TS_PUBLIC_KEY_HEX or fetched from {apiBase}/v1/scitt/ts-key; " +
        "the Bitcoin txid is taken from the statement wrapper, the `txid` arg, or " +
        "a /v1/scitt anchor lookup. SCITT verification requires the SDK's scitt " +
        "module to be present in the installed build.",
      inputSchema: {
        sequence: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .describe("Sequence number of a receipt to verify via the API."),
        transparent_statement: z
          .unknown()
          .optional()
          .describe(
            "A SCITT Transparent Statement (COSE_Sign1 with attached COSE " +
              "Receipts) in SERIALIZED form: a base64/base64url or hex string, " +
              "or a wrapper object { transparent_statement: <string>, txid? }. " +
              "Verified locally (a fully decoded COSE object is not accepted)."
          ),
        txid: z
          .string()
          .optional()
          .describe(
            "Bitcoin transaction id holding the daily-root OP_RETURN, if known. " +
              "Used for the §7 step-5 witness when not embedded in the statement."
          ),
        issuer_public_key_hex: z
          .string()
          .regex(SHA256_HEX, "must be 64 hex characters (32-byte Ed25519 key)")
          .optional()
          .describe(
            "Issuer (publisher) Ed25519 PUBLIC key as 64 hex chars, to verify " +
              "the Signed Statement signature (step 1). If omitted, the issuer " +
              "key embedded/kid-resolved in the statement is used if available."
          ),
        bitcoin_check: z
          .boolean()
          .default(true)
          .describe(
            "For a Transparent Statement, also confirm the daily root in a " +
              "Bitcoin OP_RETURN via a public source."
          ),
      },
      annotations: {
        title: "Verify a transparency receipt",
        readOnlyHint: true,
        openWorldHint: true,
      },
    },
    async (args) => {
      const hasSeq = typeof args.sequence === "number";
      const hasTs =
        args.transparent_statement !== undefined &&
        args.transparent_statement !== null;

      if (hasSeq === hasTs) {
        return errorResult(
          "Provide exactly one of {sequence} or {transparent_statement}."
        );
      }

      try {
        if (hasSeq) {
          const entry = await client.verify(args.sequence as number);
          const anchor = readAnchor(
            entry as unknown as Record<string, unknown>
          );
          return jsonResult({
            mode: "sequence",
            found: Boolean(entry),
            entry,
            anchor_status: anchor.anchor_status,
            bitcoin: {
              txid: anchor.txid,
              block_height: anchor.block_height,
            },
          });
        }

        // ── SCITT Transparent Statement path (guarded — may be unavailable) ──
        // 1. Coerce the loose input to raw COSE_Sign1 bytes (+ any wrapper txid).
        const coerced = coerceTransparentStatement(args.transparent_statement);

        // 2. Load the Transparency-Service PUBLIC key for the receipt signature
        //    (step 4). Without it the receipt sig cannot be confirmed.
        let tsPublicKey: Uint8Array | undefined;
        try {
          tsPublicKey = getTsPublicKey ? await getTsPublicKey() : undefined;
        } catch (keyErr) {
          // A malformed env key etc. — report, but still run steps 1-3.
          const reason =
            keyErr instanceof Error ? keyErr.message : String(keyErr);
          console.error(`[ledgerproof-mcp] TS public key unavailable: ${reason}`);
          tsPublicKey = undefined;
        }

        // 3. Optional issuer public key override (step 1).
        const issuerPublicKey =
          typeof args.issuer_public_key_hex === "string"
            ? pubKeyHexToBytes(args.issuer_public_key_hex)
            : undefined;

        // 4. Resolve the Bitcoin txid: explicit arg → wrapper → /v1/scitt lookup.
        //    (The lookup needs the root, which the verifier recomputes; so we
        //    run once without bitcoin to learn the root, then re-check Bitcoin
        //    only if a txid surfaces and a bitcoin check was requested.)
        let txid =
          (typeof args.txid === "string" && args.txid.length > 0
            ? args.txid
            : undefined) ?? coerced.txid;

        const baseOpts = {
          ...(issuerPublicKey ? { issuerPublicKey } : {}),
          ...(tsPublicKey ? { tsPublicKey } : {}),
        };

        let result = await verifyTransparentStatement(coerced.bytes, {
          ...baseOpts,
          bitcoinCheck: Boolean(args.bitcoin_check) && Boolean(txid),
          ...(txid ? { txid } : {}),
        });

        // If a Bitcoin check was asked for but we had no txid, try to look one
        // up from the recomputed root, then re-run just the witness step.
        if (args.bitcoin_check && !txid) {
          const recomputedRoot =
            typeof result["recomputedRoot"] === "string"
              ? (result["recomputedRoot"] as string)
              : "";
          const looked = await lookupAnchorTxid(recomputedRoot);
          if (looked) {
            txid = looked;
            result = await verifyTransparentStatement(coerced.bytes, {
              ...baseOpts,
              bitcoinCheck: true,
              txid,
            });
          }
        }

        return jsonResult({
          mode: "transparent_statement",
          issuerSignatureValid: result.issuerSignatureValid,
          inclusionProofValid: result.inclusionProofValid,
          receiptSignatureValid: result.receiptSignatureValid,
          bitcoinConfirmed: result.bitcoinConfirmed ?? false,
          valid: result.valid,
          recomputedRoot: result["recomputedRoot"] ?? null,
          // Honest provenance of the inputs used for the check.
          ts_public_key: {
            available: Boolean(tsPublicKey),
            source: summary.tsPublicKeySource,
            fingerprint: summary.tsPublicKeyFingerprint ?? null,
          },
          bitcoin: {
            checked: Boolean(args.bitcoin_check),
            txid: txid ?? null,
          },
        });
      } catch (err) {
        if (err instanceof ScittUnavailableError) {
          return errorResult(err.message);
        }
        const reason = err instanceof Error ? err.message : String(err);
        return errorResult(`Verification failed: ${reason}`);
      }
    }
  );

  // ── Tool 3: check anchor status (poll target) ──────────────────────────
  server.registerTool(
    "ledgerproof_check_anchor",
    {
      title: "Check Bitcoin anchor status",
      description:
        "Check whether a receipt's daily Merkle root has been anchored to " +
        "Bitcoin yet. Returns anchor_status ('pending' or 'anchored') and, " +
        "when anchored, the Bitcoin txid, block height/hash, and Merkle " +
        "inclusion proof. Agents should poll this with the receipt's sequence " +
        "after issuance until anchor_status becomes 'anchored' (the anchor is " +
        "batched daily, so this can take time).",
      inputSchema: {
        sequence: z
          .number()
          .int()
          .nonnegative()
          .describe("Sequence number returned by ledgerproof_issue_receipt."),
      },
      annotations: {
        title: "Check Bitcoin anchor status",
        readOnlyHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (args) => {
      try {
        const entry = await client.verify(args.sequence);
        if (!entry) {
          return errorResult(
            `No entry found for sequence ${args.sequence}. It may not be ` +
              "registered yet, or the sequence is wrong."
          );
        }
        const anchor = readAnchor(
          entry as unknown as Record<string, unknown>
        );
        return jsonResult({
          sequence: args.sequence,
          anchor_status: anchor.anchor_status,
          txid: anchor.txid,
          block_height: anchor.block_height,
          block_hash: anchor.block_hash,
          merkle_proof: anchor.merkle_proof,
          anchored_at: anchor.anchored_at,
          poll_again:
            anchor.anchor_status === "pending"
              ? "Anchoring is batched (daily). Poll again later."
              : null,
        });
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        return errorResult(`Failed to check anchor: ${reason}`);
      }
    }
  );

  // ── Tool 4: hash an artifact locally ───────────────────────────────────
  server.registerTool(
    "ledgerproof_hash_artifact",
    {
      title: "Hash an artifact (SHA-256)",
      description:
        "Compute the SHA-256 (hex) of a payload using the SDK's hashing. " +
        "PRIVACY: use this to obtain a precomputed hash so raw payloads never " +
        "leave the machine — then pass the hash to ledgerproof_issue_receipt as " +
        "precomputed_sha256. Over Streamable HTTP, issue_receipt REQUIRES " +
        "precomputed_sha256 and rejects raw payloads, so hash locally first.",
      inputSchema: {
        payload: z
          .string()
          .describe("The content to hash (UTF-8 text). Returned only as a hash."),
      },
      annotations: {
        title: "Hash an artifact (SHA-256)",
        readOnlyHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) => {
      // artifactHash and sha256Hex are identical here; use artifactHash to
      // make intent explicit. Both come from @ledgerproof/sdk.
      const hex = artifactHash(args.payload);
      return jsonResult({
        sha256: hex,
        algorithm: "SHA-256",
        bytes: new TextEncoder().encode(args.payload).length,
        // Equivalent to sha256Hex(payload); proves we use the SDK primitive.
        verify: hex === sha256Hex(args.payload),
      });
    }
  );

  // ── Scoped prompt: when (and when NOT) to issue a receipt ───────────────
  server.registerPrompt(
    "ledgerproof_when_to_issue",
    {
      title: "When to issue a LedgerProof receipt",
      description:
        "Guidance on the narrow situations where issuing a LedgerProof " +
        "Article-50 receipt is appropriate, and the cost that makes it a " +
        "deliberate action.",
    },
    () => ({
      messages: [
        {
          role: "assistant" as const,
          content: {
            type: "text" as const,
            text:
              "Use ledgerproof_issue_receipt ONLY when you are deliberately " +
              "producing an Article-50 transparency record for a specific piece " +
              "of AI-generated content — i.e. content a deployer must disclose " +
              "as AI-generated under EU AI Act Article 50, and for which a " +
              "durable, independently verifiable provenance record is wanted.\n\n" +
              "Issuing is NOT free and NOT reversible: each receipt's daily " +
              "Merkle root is anchored to Bitcoin via an OP_RETURN, which costs " +
              "a real Bitcoin transaction fee. Treat issuance as a deliberate, " +
              "user-intended action.\n\n" +
              "DO issue when: the user explicitly asks to create/log/anchor a " +
              "transparency or provenance receipt for a finished AI artifact; or " +
              "a documented compliance workflow calls for an Article-50 record.\n\n" +
              "DO NOT auto-fire on loose triggers such as: the mere mention of " +
              "AI, EU AI Act, compliance, or Bitcoin; every chat message or draft; " +
              "intermediate/exploratory outputs; or speculative 'might be useful' " +
              "cases. When unsure, ask the user to confirm before issuing.\n\n" +
              "Privacy: prefer hashing locally (ledgerproof_hash_artifact) and " +
              "passing precomputed_sha256 so raw content never leaves the machine; " +
              "over Streamable HTTP this is required.\n\n" +
              "After issuing, anchoring is asynchronous: the receipt returns " +
              "anchor_status 'pending'. Poll ledgerproof_check_anchor until it is " +
              "'anchored'.\n\n" +
              "Honest wording: LedgerProof implements the IETF SCITT architecture " +
              "drafts (draft-ietf-scitt-architecture-22) with COSE Receipts " +
              "(draft-ietf-cose-merkle-tree-proofs-18), additionally anchored to " +
              "Bitcoin. Do NOT describe it as an RFC, standard, certified, or " +
              "'SCITT compliant'.\n\n" +
              `Active publisher: ${summary.publisherId} (deployer country ` +
              `${summary.deployerCountry}). API base: ${summary.apiBase}.`,
          },
        },
      ],
    })
  );

  return server;
}
