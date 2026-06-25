# @ledgerproof/mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets any
MCP client (Claude Desktop, Claude Code, IDEs, agents) issue and verify
**EU AI Act Article 50 transparency receipts** through
[`@ledgerproof/sdk`](../typescript).

LedgerProof **implements the IETF SCITT architecture drafts**
(`draft-ietf-scitt-architecture-22`) with **COSE Receipts**
(`draft-ietf-cose-merkle-tree-proofs-18`), and additionally anchors a daily
Merkle root to **Bitcoin** (OP_RETURN). It is an early implementation of live
IETF Internet-Drafts — **not an RFC, not a standard, not certified, not "SCITT
compliant."** That precision is deliberate; please keep it in any derived copy.

> Issuing a receipt is a real, deliberate action: each receipt's daily Merkle
> root is anchored to Bitcoin, which **costs a Bitcoin transaction fee**. Do not
> wire agents to auto-issue on loose triggers. The bundled
> `ledgerproof_when_to_issue` prompt spells out when issuance is (and isn't)
> appropriate.

## Transports

This server speaks the two **current** MCP transports. The deprecated
HTTP+SSE transport is intentionally **not** used.

- **stdio** (default) — for local clients that launch the server as a subprocess.
- **Streamable HTTP** (`StreamableHTTPServerTransport`) — for networked clients.
  In this mode `ledgerproof_issue_receipt` **requires `precomputed_sha256` and
  rejects raw payloads**, so artifact bytes never cross the network.

## Tools

| Tool | Purpose |
|---|---|
| `ledgerproof_issue_receipt` | Produce an Article-50 record for AI-generated content and register it. Exactly one of `artifact` or `precomputed_sha256`, plus `aiSystemId`, `deployerName`, `contentCategory`, etc. Mirrors `publishAiArticle50`. Returns `{sequence, entry_hash, verify_url, anchor_status:"pending"}`. |
| `ledgerproof_verify_receipt` | Verify by `{sequence}` (API lookup) **or** `{transparent_statement}` (SCITT bundle, trust-minimized §7 check → `{issuerSignatureValid, inclusionProofValid, receiptSignatureValid, bitcoinConfirmed, valid}`). |
| `ledgerproof_check_anchor` | Poll a `{sequence}` for Bitcoin anchor status (`pending` → `anchored` with `txid`, block, Merkle proof). |
| `ledgerproof_hash_artifact` | SHA-256 a `{payload}` locally so raw content never leaves the machine. |

### Prompt

- `ledgerproof_when_to_issue` — scoped guidance: issue **only** when deliberately
  "producing an Article-50 transparency record for AI-generated content," and a
  reminder that anchoring costs a Bitcoin tx fee, so do not auto-fire on loose
  triggers.

## Honest behavior notes / gaps

- **Anchoring is asynchronous.** Issuance always returns
  `anchor_status: "pending"`. The server never reports a fabricated "anchored"
  status — `ledgerproof_check_anchor` reports `anchored` only when the API
  returns a real Bitcoin `txid`. Poll until then.
- **Raw payloads stay local even on stdio.** The SDK hashes the artifact locally
  and only the `artifact_hash` (never the bytes) is sent to the LedgerProof API.
  Streamable HTTP additionally keeps the bytes off the *MCP* hop by requiring
  `precomputed_sha256`.
- **SCITT verification is guarded.** `verifyTransparentStatement` lives in the
  SDK's `scitt/` module, which is being built in parallel and **may not be
  exported yet**. If it's absent, `ledgerproof_verify_receipt` (Transparent
  Statement mode) returns a clear "not available in the installed SDK" error
  instead of failing the build. Sequence-mode verification works today.
- **`precomputed_sha256` issuance depends on an SDK feature.** The base
  `publishAiArticle50` always hashes raw bytes and exposes no precomputed-hash
  entrypoint. The server passes the hash through optimistically (forward-compat);
  if the installed SDK can't accept it, the tool returns a precise error rather
  than registering a record with the wrong `artifact_hash`. Until the SDK adds a
  precomputed-hash publish path, issue from raw `artifact` over **stdio**.

## Configuration (environment variables)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `LEDGERPROOF_PUBLISHER_ID` | yes | — | Legal-entity id (LEI/EUID/VAT/DID). Not an email. |
| `LEDGERPROOF_DEPLOYER_COUNTRY` | yes | — | ISO country code, e.g. `DE`. |
| `LEDGERPROOF_API_KEY` | yes | — | LedgerProof API key. |
| `LEDGERPROOF_API_BASE` | no | `https://api-eu.ledgerproofhq.io` | API base URL (`api-eu.ledgerproofhq.io`). |
| `LEDGERPROOF_SIGNING_KEY_HEX` | no | ephemeral | Ed25519 signing seed (hex). **Never logged.** |
| `LEDGERPROOF_KEY_PATH` | no | — | Path to a file containing the hex seed (alt to `_HEX`). |
| `LEDGERPROOF_KEY_ID` | no | `default` | Key id registered with the service. |

HTTP-only (optional): `PORT`/`LEDGERPROOF_MCP_PORT` (default `3000`),
`LEDGERPROOF_MCP_HOST` (default `127.0.0.1`),
`LEDGERPROOF_MCP_TRANSPORT=http` (same as `--http`).

> The Ed25519 signing key is never logged, never returned by any tool, and never
> serialized. Only its presence (`provided` vs `ephemeral`) is printed at boot.

## Install / build

```bash
npm install
npm run build      # tsc → dist/
npm run lint       # tsc --noEmit
```

## Run

```bash
# stdio (default)
npx @ledgerproof/mcp-server

# Streamable HTTP on http://127.0.0.1:3000/mcp
npx @ledgerproof/mcp-server --http --port 3000
```

## MCP client config

### stdio

```json
{
  "mcpServers": {
    "ledgerproof": {
      "command": "npx",
      "args": ["-y", "@ledgerproof/mcp-server"],
      "env": {
        "LEDGERPROOF_PUBLISHER_ID": "LEI:5493001KJTIIGC8Y1R12",
        "LEDGERPROOF_DEPLOYER_COUNTRY": "DE",
        "LEDGERPROOF_API_KEY": "sk_live_...",
        "LEDGERPROOF_API_BASE": "https://api-eu.ledgerproofhq.io",
        "LEDGERPROOF_SIGNING_KEY_HEX": "<32-byte-hex-ed25519-seed>",
        "LEDGERPROOF_KEY_ID": "default"
      }
    }
  }
}
```

### Streamable HTTP

Start the server (`npx @ledgerproof/mcp-server --http --port 3000`), then point
the client at the URL:

```json
{
  "mcpServers": {
    "ledgerproof": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:3000/mcp"
    }
  }
}
```

Over Streamable HTTP, call `ledgerproof_hash_artifact` first and pass the result
to `ledgerproof_issue_receipt` as `precomputed_sha256` — raw payloads are
rejected on this transport by design.

## License

Apache-2.0
