/**
 * SCITT bridge — guarded access to the SDK's Transparent Statement verifier.
 *
 * Per the approved SCITT profile (§9), `verifyTransparentStatement(...)` lives
 * in the `scitt/` module of `@ledgerproof/sdk`. It may not yet be present in
 * the *installed* build of the SDK (the dist can lag the source while Phase 1
 * ships), so we resolve it dynamically at call time and fail with a clear,
 * honest error if it is unavailable — rather than breaking the MCP server's
 * build or pretending the capability exists.
 *
 * This module also adapts the MCP tool's loose `transparent_statement` input
 * (a base64/hex string, raw bytes, or a small wrapper object carrying the
 * statement + an anchor txid) into the exact byte form + options the SDK
 * verifier requires (spec §7): the issuer key, the Transparency-Service PUBLIC
 * key (for the Receipt signature), and the Bitcoin txid (for the OP_RETURN
 * witness).
 *
 * Honest positioning: LedgerProof implements the IETF SCITT architecture
 * (draft-ietf-scitt-architecture-22) with COSE Receipts
 * (draft-ietf-cose-merkle-tree-proofs-18), additionally anchored to Bitcoin.
 * It is NOT an RFC, standard, or certified profile.
 */

/** The trust-minimized result of the §7 verification algorithm. */
export interface TransparentStatementVerification {
  /** Step 1: Issuer COSE_Sign1 signature over the Signed Statement is valid. */
  issuerSignatureValid: boolean;
  /** Steps 2-3: RFC 9162 inclusion proof recomputes the logged root. */
  inclusionProofValid: boolean;
  /** Step 4: Receipt COSE_Sign1 (TS key) is valid and matches the root. */
  receiptSignatureValid: boolean;
  /** Step 5 (LedgerProof bonus): root confirmed in a Bitcoin OP_RETURN. */
  bitcoinConfirmed?: boolean;
  /** Valid iff steps 1-4 pass. None of 1-4 requires trusting the API. */
  valid: boolean;
  [k: string]: unknown;
}

/**
 * Options we pass through to the SDK verifier. Mirrors the SDK's `VerifyOptions`
 * (kept local so the MCP server typechecks even against an SDK build whose dist
 * has not yet exported the scitt types).
 */
export interface VerifyTransparentStatementOptions {
  /** Issuer public key (32 bytes) for the Signed Statement signature (step 1). */
  issuerPublicKey?: Uint8Array;
  /** Transparency-Service PUBLIC key (32 bytes) for the Receipt sig (step 4). */
  tsPublicKey?: Uint8Array;
  /** Independently confirm the daily root on Bitcoin via a public source. */
  bitcoinCheck?: boolean;
  /** Bitcoin transaction id holding the OP_RETURN anchor (for `bitcoinCheck`). */
  txid?: string;
  /** Override the mempool-style explorer API base. */
  mempoolApiBase?: string;
  /** Injectable fetch (defaults to globalThis.fetch in the SDK). */
  fetch?: typeof fetch;
}

type VerifyTsFn = (
  ts: Uint8Array,
  options?: VerifyTransparentStatementOptions
) => Promise<TransparentStatementVerification>;

/** Raised when the SCITT verifier is not yet present in the installed SDK. */
export class ScittUnavailableError extends Error {
  constructor(detail?: string) {
    super(
      "SCITT Transparent Statement verification is not available in the " +
        "installed @ledgerproof/sdk build yet (the scitt/ module is present in " +
        "source but verifyTransparentStatement is not exported from the built " +
        "dist). Rebuild/upgrade the SDK so its dist exports the scitt module, " +
        "or use ledgerproof_verify_receipt with a {sequence} instead." +
        (detail ? ` (${detail})` : "")
    );
    this.name = "ScittUnavailableError";
  }
}

let cached: VerifyTsFn | null | undefined;

/**
 * Resolve `verifyTransparentStatement` from the SDK if (and only if) it has
 * been exported. We probe the main entry and the conventional `./scitt`
 * subpath. The dynamic specifier is held in a variable so the compiler does
 * not statically require a subpath that may not exist yet.
 */
async function resolveVerifier(): Promise<VerifyTsFn | null> {
  if (cached !== undefined) return cached;

  const candidates: string[] = ["@ledgerproof/sdk", "@ledgerproof/sdk/scitt"];
  for (const spec of candidates) {
    try {
      const mod: Record<string, unknown> = await import(spec);
      const fn = mod["verifyTransparentStatement"];
      if (typeof fn === "function") {
        cached = fn as VerifyTsFn;
        return cached;
      }
    } catch {
      // Subpath may not exist yet — keep probing, then fall through to null.
    }
  }
  cached = null;
  return cached;
}

// ── Input adaptation ────────────────────────────────────────────────────────

/** What a caller may hand us as the Transparent Statement + optional anchor. */
export interface TransparentStatementInput {
  /** The Transparent Statement bytes/string, or a wrapper carrying them. */
  statement: unknown;
  /** A txid extracted from a wrapper, if the caller provided one alongside. */
  extractedTxid?: string;
}

const HEX_RE = /^[0-9a-fA-F]+$/;

function base64ToBytes(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(norm, "base64"));
}

function hexToBytes(s: string): Uint8Array {
  const clean = s.startsWith("0x") ? s.slice(2) : s;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Coerce the loose `transparent_statement` MCP input into the raw COSE_Sign1
 * bytes the SDK verifier needs, plus any anchor txid found in a wrapper.
 *
 * Accepted forms:
 *   - Uint8Array / ArrayBuffer / Buffer / number[]  → used as-is.
 *   - base64 / base64url / hex string               → decoded to bytes.
 *   - { transparent_statement | statement | ts | bytes, txid?, anchor? }
 *       → unwrap the inner statement (recursively) and lift a txid if present.
 *
 * We deliberately do NOT accept a fully *decoded* COSE object/array: re-encoding
 * it could change the signed bytes and silently break signature verification.
 * Callers must pass the statement in its serialized (string/bytes) form.
 */
export function coerceTransparentStatement(
  input: unknown
): { bytes: Uint8Array; txid?: string } {
  // Direct byte forms.
  if (input instanceof Uint8Array) return { bytes: input };
  if (input instanceof ArrayBuffer) return { bytes: new Uint8Array(input) };
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(input)) {
    return { bytes: new Uint8Array(input as Buffer) };
  }
  if (Array.isArray(input) && input.every((n) => typeof n === "number")) {
    return { bytes: Uint8Array.from(input as number[]) };
  }

  // String forms: prefer base64 (the canonical wire form), fall back to hex.
  if (typeof input === "string") {
    const s = input.trim();
    if (s.length === 0) throw new Error("transparent_statement string is empty");
    // Even-length pure-hex → treat as hex; otherwise base64/base64url.
    if (s.length % 2 === 0 && HEX_RE.test(s)) {
      return { bytes: hexToBytes(s) };
    }
    return { bytes: base64ToBytes(s) };
  }

  // Wrapper object: lift the inner statement and an optional txid. The field
  // names mirror the backend `GET /v1/scitt/receipt/{sequence}` response so a
  // caller can pass that JSON body through verbatim: it carries
  // `transparent_statement_base64` (+ `signed_statement_base64`) and `btc_txid`.
  if (input && typeof input === "object") {
    const obj = input as Record<string, unknown>;
    const txid = extractTxidFromWrapper(obj);
    const inner =
      obj["transparent_statement_base64"] ?? // backend receipt endpoint (primary)
      obj["transparent_statement"] ??
      obj["signed_statement_base64"] ?? // backend, pre-anchor fallback
      obj["statement"] ??
      obj["ts"] ??
      obj["bytes"] ??
      obj["cose"] ??
      obj["value"];
    if (inner !== undefined && inner !== input) {
      const got = coerceTransparentStatement(inner);
      return { bytes: got.bytes, txid: got.txid ?? txid };
    }
  }

  throw new Error(
    "transparent_statement must be a base64/hex string, raw bytes, or a " +
      "wrapper object { transparent_statement: <string|bytes>, txid? }. A " +
      "fully decoded COSE object is not accepted (re-encoding could break the " +
      "signature)."
  );
}

/**
 * Pull a Bitcoin txid out of a caller-supplied wrapper, if present.
 *
 * The backend `GET /v1/scitt/receipt/{sequence}` response names this field
 * `btc_txid`, so that is the primary key; `txid` / `bitcoin_txid` / `anchor_txid`
 * (and a nested `anchor` object) are accepted as fallbacks for other callers.
 */
export function extractTxidFromWrapper(
  obj: Record<string, unknown>
): string | undefined {
  const direct =
    obj["btc_txid"] ?? // backend receipt endpoint (primary)
    obj["txid"] ??
    obj["bitcoin_txid"] ??
    obj["anchor_txid"] ??
    (typeof obj["anchor"] === "object" && obj["anchor"]
      ? (obj["anchor"] as Record<string, unknown>)["txid"] ??
        (obj["anchor"] as Record<string, unknown>)["btc_txid"] ??
        (obj["anchor"] as Record<string, unknown>)["bitcoin_txid"]
      : undefined);
  return typeof direct === "string" && direct.length > 0 ? direct : undefined;
}

/**
 * Verify a SCITT Transparent Statement using the SDK's §7 algorithm.
 * Throws {@link ScittUnavailableError} if the SDK does not yet export it.
 *
 * `tsRaw` is the raw COSE_Sign1 bytes (already coerced from the tool input).
 */
export async function verifyTransparentStatement(
  tsRaw: Uint8Array,
  options: VerifyTransparentStatementOptions = { bitcoinCheck: true }
): Promise<TransparentStatementVerification> {
  const fn = await resolveVerifier();
  if (!fn) throw new ScittUnavailableError();
  return fn(tsRaw, options);
}
