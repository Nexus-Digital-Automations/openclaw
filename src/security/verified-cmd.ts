/**
 * Owner: security/verified-cmd.
 *
 * Tool-call envelope (P1.1). Every tool call extracted from a model stream is
 * wrapped in `{ call, nonce, provenance, prevHash }` before dispatch. The
 * dispatcher refuses any call whose envelope does not chain to the previous
 * envelope of the same turn.
 *
 * Invariants:
 *  - `nonce` is 256 bits of `crypto.randomBytes` hex. Unguessable, never
 *    reused, never exposed to the model.
 *  - `prevHash` is SHA-256 of the canonical serialization of the previous
 *    envelope in the same turn. The first envelope of a turn uses 64 zeros.
 *  - Serialization is deterministic: recursive sorted-key JSON with no
 *    whitespace, matching the shape used by `audit-chain` for `argvHash`.
 *  - Envelopes are turn-scoped runtime objects. They are NOT persisted; the
 *    chain head is held in memory beside the per-turn firewall instance.
 *
 * Non-goals (deferred):
 *  - Nonce table / replay rejection lifecycle (P1.2).
 *  - Schema fuzz hardening of the `call.args` shape (P1.3).
 */
import { createHash, randomBytes } from "node:crypto";

export const GENESIS_PREV_HASH = "0".repeat(64);

export type VerifiedCmdProvenance = "model" | "system";

export type VerifiedCmdCall = {
  name: string;
  args: unknown;
};

export type VerifiedCmdEnvelope = {
  call: VerifiedCmdCall;
  nonce: string;
  provenance: VerifiedCmdProvenance;
  prevHash: string;
};

export type VerifyEnvelopeResult = { ok: true } | { ok: false; reason: string };

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).toSorted();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${parts.join(",")}}`;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Canonical bytes of an envelope used both for `prevHash` chaining and for
 * tamper detection inside `verifyEnvelope`. Keys are emitted in sorted order
 * so two semantically-equal envelopes hash to the same digest.
 */
export function serializeEnvelope(envelope: VerifiedCmdEnvelope): string {
  return canonicalJson({
    call: envelope.call,
    nonce: envelope.nonce,
    prevHash: envelope.prevHash,
    provenance: envelope.provenance,
  });
}

/**
 * Hash of the canonical serialization. Used by the next envelope in the turn
 * as its `prevHash` value.
 */
export function envelopeHash(envelope: VerifiedCmdEnvelope): string {
  return sha256Hex(serializeEnvelope(envelope));
}

/**
 * Mint an envelope for a freshly-extracted tool call. Caller is responsible
 * for tracking the per-turn chain head and feeding the previous envelope's
 * hash in as `prevHash`. First envelope of a turn passes `GENESIS_PREV_HASH`.
 */
export function mintEnvelope(
  call: VerifiedCmdCall,
  provenance: VerifiedCmdProvenance,
  prevHash: string,
): VerifiedCmdEnvelope {
  if (typeof call.name !== "string" || call.name.length === 0) {
    throw new Error("mintEnvelope: call.name must be a non-empty string");
  }
  if (typeof prevHash !== "string" || prevHash.length !== 64) {
    throw new Error("mintEnvelope: prevHash must be a 64-char hex digest");
  }
  return {
    call: { name: call.name, args: call.args ?? null },
    nonce: randomBytes(32).toString("hex"),
    provenance,
    prevHash,
  };
}

/**
 * Verify envelope shape and chain linkage against the dispatcher's expected
 * previous hash. Returns a discriminated union — callers branch on `ok` and
 * surface `reason` in structured logs / error codes. No exceptions for the
 * expected failure modes (shape, chain break) because dispatch needs to
 * distinguish them cleanly from runtime errors.
 */
export function verifyEnvelope(
  envelope: VerifiedCmdEnvelope | null | undefined,
  expectedPrevHash: string,
): VerifyEnvelopeResult {
  if (!envelope || typeof envelope !== "object") {
    return { ok: false, reason: "envelope_missing" };
  }
  if (!envelope.call || typeof envelope.call !== "object") {
    return { ok: false, reason: "envelope_shape_invalid_call" };
  }
  if (typeof envelope.call.name !== "string" || envelope.call.name.length === 0) {
    return { ok: false, reason: "envelope_shape_invalid_name" };
  }
  if (typeof envelope.nonce !== "string" || envelope.nonce.length !== 64) {
    return { ok: false, reason: "envelope_shape_invalid_nonce" };
  }
  if (envelope.provenance !== "model" && envelope.provenance !== "system") {
    return { ok: false, reason: "envelope_shape_invalid_provenance" };
  }
  if (typeof envelope.prevHash !== "string" || envelope.prevHash.length !== 64) {
    return { ok: false, reason: "envelope_shape_invalid_prev_hash" };
  }
  if (envelope.prevHash !== expectedPrevHash) {
    return { ok: false, reason: "chain_break" };
  }
  return { ok: true };
}
