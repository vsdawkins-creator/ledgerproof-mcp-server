/**
 * The typed API an AI helper sees in Code Mode (AGNOSTIC-PLAN.md Phase 4).
 * Shown to the model verbatim as the `ledgerproof_execute` tool description.
 */
export const LEDGERPROOF_API_DTS = `
// Code Mode: write an async JavaScript function body. It runs in an isolated
// sandbox with NO network, NO filesystem and NO access to API keys. Use the
// \`lp\` object below; read your data from \`input\`; \`return\` a small result
// (only the return value reaches your context — return exceptions, counts or
// summaries, not whole datasets).

declare const input: unknown; // whatever JSON you passed in the tool's \`input\` field

declare const lp: {
  /** SHA-256 hex of UTF-8 text, computed locally. Free. */
  hash(text: string): Promise<string>;

  /** Look up a receipt by sequence. Free. */
  verify(sequence: number): Promise<{
    sequence: number;
    found: boolean;
    entry_hash: string | null;
    anchor_status: "pending" | "anchored" | "unknown";
    txid: string | null;
    block_height: number | null;
  }>;

  /** Trust-minimised check of a SCITT Transparent Statement (base64/hex/bytes). Free. */
  verifyStatement(statement: string): Promise<{
    issuerSignatureValid: boolean;
    inclusionProofValid: boolean;
    receiptSignatureValid: boolean;
    valid: boolean;
  }>;

  /** Bitcoin anchor status for a sequence. "anchored" only with a real txid. Free. */
  anchor(sequence: number): Promise<{
    sequence: number;
    anchor_status: "pending" | "anchored" | "unknown";
    txid: string | null;
  }>;

  /**
   * PLAN an Article-50 receipt. Nothing is issued here: issuing costs a real
   * Bitcoin fee and is irreversible, so planned receipts are collected into a
   * plan that a HUMAN must approve via ledgerproof_commit_plan. Hash-only:
   * pass precomputed_sha256 (64 hex chars), never raw content. Duplicate
   * hashes are ignored. A per-run budget applies.
   */
  issue(record: {
    precomputed_sha256: string;
    aiSystemId: string;
    deployerName: string;
    contentCategory:
      | "SYNTHETIC_TEXT" | "SYNTHETIC_IMAGE" | "SYNTHETIC_AUDIO" | "SYNTHETIC_VIDEO"
      | "DEEPFAKE" | "SYNTHETIC_MULTIMODAL" | "AI_ASSISTED_DOCUMENT";
  }): Promise<{ planned: true; position: number } | { planned: false; reason: string }>;
};
`;
