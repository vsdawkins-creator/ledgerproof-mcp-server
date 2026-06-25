/**
 * Configuration for the LedgerProof MCP server, sourced from environment.
 *
 * SECURITY: the Ed25519 signing key is the most sensitive value here. It is
 * never logged, never echoed in tool responses, and never serialized. Only its
 * presence (boolean) is ever surfaced. Read this file with that invariant in
 * mind before adding any console output.
 */

import { readFileSync } from "node:fs";

import { LedgerProof, sha256Hex } from "@ledgerproof/sdk";
import type { LedgerProofConfig } from "@ledgerproof/sdk";

export const DEFAULT_API_BASE = "https://api-eu.ledgerproofhq.io";

/** Path of the public Transparency-Service key endpoint (relative to apiBase). */
export const TS_KEY_PATH = "/v1/scitt/ts-key";

const TS_KEY_HEX_RE = /^[0-9a-f]{64}$/i;

/** Resolved, non-secret view of the server configuration (safe to log). */
export interface SafeConfigSummary {
  publisherId: string;
  deployerCountry: string;
  apiBase: string;
  keyId: string;
  hasApiKey: boolean;
  hasSigningKey: boolean;
  /**
   * Source of the Transparency-Service PUBLIC key, if known at boot:
   * "env" (LEDGERPROOF_TS_PUBLIC_KEY_HEX) or "endpoint" (fetched lazily) or
   * "none". The TS key is PUBLIC, so a fingerprint is safe to surface.
   */
  tsPublicKeySource: "env" | "endpoint" | "none";
  /** Short SHA-256 fingerprint of the TS public key (PUBLIC — safe to log). */
  tsPublicKeyFingerprint?: string;
}

export interface ResolvedConfig {
  /** A ready-to-use SDK client. */
  client: LedgerProof;
  /** Non-secret summary, safe to print to stderr on boot. */
  summary: SafeConfigSummary;
  /**
   * Lazily resolve the Transparency-Service PUBLIC verification key (32 bytes).
   *
   * Resolution order (spec §7 step 4 needs this key to check the Receipt sig):
   *   1. LEDGERPROOF_TS_PUBLIC_KEY_HEX (64 hex chars) — no network.
   *   2. GET {apiBase}/v1/scitt/ts-key — fetched once and cached for the process.
   *
   * Returns undefined if neither is available (the verifier then reports
   * receiptSignatureValid:false rather than trusting the API). The key is
   * PUBLIC; only a fingerprint is ever logged, never raw key material is
   * treated as a secret here, but we still avoid dumping it wholesale.
   */
  getTsPublicKey: () => Promise<Uint8Array | undefined>;
}

function env(name: string): string | undefined {
  const v = process.env[name];
  return v && v.length > 0 ? v : undefined;
}

/** Decode a 64-char hex string to 32 bytes; throws on malformed input. */
function hexToBytes32(hex: string): Uint8Array {
  const clean = hex.trim();
  if (!TS_KEY_HEX_RE.test(clean)) {
    throw new Error(
      "Transparency-Service public key must be 64 hex characters (32 bytes)"
    );
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** First 16 hex chars of SHA-256(pubkey) — a safe, public fingerprint. */
function tsKeyFingerprint(pub: Uint8Array): string {
  return sha256Hex(pub).slice(0, 16);
}

/**
 * Exact JSON shape of `GET /v1/scitt/ts-key` (backend `main.py::scitt_ts_key`).
 * The canonical key fields are `public_key_hex` (64 hex chars) and
 * `public_key_base64` (32-byte base64). We prefer hex; base64 is the fallback.
 *
 * The legacy `public_key` alias is retained ONLY for forward/back-compat with an
 * older server build and is not emitted by the current backend.
 */
interface TsKeyResponse {
  /** 64-char hex of the 32-byte Ed25519 TS public key (primary field). */
  public_key_hex?: string;
  /** base64 of the 32-byte Ed25519 TS public key (fallback field). */
  public_key_base64?: string;
  /** Legacy alias (older builds); current backend does not send this. */
  public_key?: string;
  alg?: string;
  crv?: string;
  kty?: string;
}

/** Coerce a public-key string (hex or base64) to 32 raw bytes. */
function coercePublicKeyString(value: string): Uint8Array {
  const trimmed = value.trim();
  if (TS_KEY_HEX_RE.test(trimmed)) return hexToBytes32(trimmed);
  // Try base64 / base64url (44 or 43 chars for 32 bytes).
  const b64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const buf = Buffer.from(b64, "base64");
  if (buf.length === 32) return new Uint8Array(buf);
  throw new Error(
    "TS public key from endpoint was neither 32-byte hex nor 32-byte base64"
  );
}

/**
 * Build the lazy TS-key resolver. Caches the first successful result (env or
 * fetched) for the lifetime of the process so repeated verifications do not
 * re-hit the endpoint. `summary` is mutated in place to record the source +
 * fingerprint the first time the key is resolved via the endpoint.
 */
function makeTsKeyResolver(
  apiBase: string,
  envHex: string | undefined,
  summary: SafeConfigSummary,
  fetchImpl: typeof fetch = globalThis.fetch
): () => Promise<Uint8Array | undefined> {
  let cached: Uint8Array | undefined;
  let resolved = false;

  return async function getTsPublicKey(): Promise<Uint8Array | undefined> {
    if (resolved) return cached;

    // 1. Environment-provided hex (no network).
    if (envHex) {
      cached = hexToBytes32(envHex);
      resolved = true;
      return cached;
    }

    // 2. Fetch from the public TS-key endpoint, then cache.
    if (!fetchImpl) {
      resolved = true;
      return undefined;
    }
    const url = `${apiBase.replace(/\/$/, "")}${TS_KEY_PATH}`;
    try {
      const resp = await fetchImpl(url);
      if (!resp.ok) {
        resolved = true;
        return undefined;
      }
      const ctype = resp.headers.get("content-type") ?? "";
      let key: Uint8Array;
      if (ctype.includes("application/json")) {
        const body = (await resp.json()) as TsKeyResponse;
        // Match the backend's exact field names: public_key_hex (primary),
        // then public_key_base64, then the legacy public_key alias.
        const raw =
          body.public_key_hex ??
          body.public_key_base64 ??
          body.public_key;
        if (typeof raw !== "string") {
          resolved = true;
          return undefined;
        }
        key = coercePublicKeyString(raw);
      } else {
        // Plain text body: a hex or base64 key string.
        key = coercePublicKeyString((await resp.text()).trim());
      }
      cached = key;
      resolved = true;
      summary.tsPublicKeySource = "endpoint";
      summary.tsPublicKeyFingerprint = tsKeyFingerprint(key);
      return cached;
    } catch {
      // Network/parse failure → treat as unavailable (verifier degrades safely).
      resolved = true;
      return undefined;
    }
  };
}

/**
 * Resolve the signing key from either LEDGERPROOF_SIGNING_KEY_HEX (preferred)
 * or LEDGERPROOF_KEY_PATH (a file containing the 32-byte hex seed). Returns
 * undefined if neither is set — the SDK will then generate an ephemeral key.
 *
 * The raw key value is returned but MUST NOT be logged by callers.
 */
function resolveSigningKeyHex(): string | undefined {
  const inline = env("LEDGERPROOF_SIGNING_KEY_HEX");
  if (inline) return inline.trim();

  const keyPath = env("LEDGERPROOF_KEY_PATH");
  if (keyPath) {
    try {
      // .trim() drops trailing newlines; we never log the contents.
      return readFileSync(keyPath, "utf8").trim();
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(
        `LEDGERPROOF_KEY_PATH was set but the key file could not be read: ${reason}`
      );
    }
  }
  return undefined;
}

/**
 * Build the SDK client from environment variables. Throws a descriptive error
 * (with no secret material) if required configuration is missing.
 */
export function loadConfig(): ResolvedConfig {
  const publisherId = env("LEDGERPROOF_PUBLISHER_ID");
  const deployerCountry = env("LEDGERPROOF_DEPLOYER_COUNTRY");
  const apiKey = env("LEDGERPROOF_API_KEY");
  const apiBase = env("LEDGERPROOF_API_BASE") ?? DEFAULT_API_BASE;
  const keyId = env("LEDGERPROOF_KEY_ID") ?? "default";
  const signingKeyHex = resolveSigningKeyHex();
  const tsPublicKeyHex = env("LEDGERPROOF_TS_PUBLIC_KEY_HEX");

  const missing: string[] = [];
  if (!publisherId) missing.push("LEDGERPROOF_PUBLISHER_ID");
  if (!deployerCountry) missing.push("LEDGERPROOF_DEPLOYER_COUNTRY");
  if (!apiKey) missing.push("LEDGERPROOF_API_KEY");
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(", ")}. ` +
        `See the README for the full configuration list.`
    );
  }

  const sdkConfig: LedgerProofConfig = {
    publisherId: publisherId as string,
    deployerCountry: deployerCountry as string,
    apiKey,
    apiBase,
    keyId,
    signingKeyHex,
  };

  const client = new LedgerProof(sdkConfig);

  // Compute the TS-key fingerprint eagerly only when supplied via env (no
  // network). The key is PUBLIC, so the fingerprint is safe to print on boot.
  let tsSource: SafeConfigSummary["tsPublicKeySource"] = "none";
  let tsFingerprint: string | undefined;
  if (tsPublicKeyHex) {
    // Validate + fingerprint now so a malformed env value fails fast/visibly.
    const keyBytes = hexToBytes32(tsPublicKeyHex);
    tsSource = "env";
    tsFingerprint = tsKeyFingerprint(keyBytes);
  } else {
    // Endpoint fallback is attempted lazily on first verification.
    tsSource = "endpoint";
  }

  const summary: SafeConfigSummary = {
    publisherId: publisherId as string,
    deployerCountry: deployerCountry as string,
    apiBase,
    keyId,
    hasApiKey: Boolean(apiKey),
    hasSigningKey: Boolean(signingKeyHex),
    tsPublicKeySource: tsSource,
    tsPublicKeyFingerprint: tsFingerprint,
  };

  const getTsPublicKey = makeTsKeyResolver(apiBase, tsPublicKeyHex, summary);

  return { client, summary, getTsPublicKey };
}
