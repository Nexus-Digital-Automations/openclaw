import { describe, expect, it } from "vitest";
import {
  GENESIS_PREV_HASH,
  envelopeHash,
  mintEnvelope,
  serializeEnvelope,
  verifyEnvelope,
  type VerifiedCmdEnvelope,
} from "./verified-cmd.js";

describe("verified-cmd envelope", () => {
  it("mint+verify roundtrip succeeds for the first envelope of a turn", () => {
    const envelope = mintEnvelope(
      { name: "read", args: { path: "/tmp/a" } },
      "model",
      GENESIS_PREV_HASH,
    );
    expect(envelope.nonce).toHaveLength(64);
    expect(envelope.provenance).toBe("model");
    expect(envelope.prevHash).toBe(GENESIS_PREV_HASH);
    expect(verifyEnvelope(envelope, GENESIS_PREV_HASH)).toEqual({ ok: true });
  });

  it("chains two envelopes within a turn via serialized hash", () => {
    const first = mintEnvelope({ name: "read", args: { path: "/a" } }, "model", GENESIS_PREV_HASH);
    const head = envelopeHash(first);
    const second = mintEnvelope({ name: "write", args: { path: "/b" } }, "model", head);
    expect(verifyEnvelope(second, head)).toEqual({ ok: true });
    expect(second.prevHash).toBe(head);
    expect(second.nonce).not.toBe(first.nonce);
  });

  it("breaks verify when the call field is tampered after mint", () => {
    const envelope = mintEnvelope(
      { name: "read", args: { path: "/a" } },
      "model",
      GENESIS_PREV_HASH,
    );
    const tampered: VerifiedCmdEnvelope = {
      ...envelope,
      call: { name: "exec", args: { cmd: "rm -rf /" } },
    };
    // Tampered envelope hashes differently — chain head computed pre-tamper
    // no longer matches; the *next* envelope's verify will fail with chain_break.
    const headFromOriginal = envelopeHash(envelope);
    const headFromTampered = envelopeHash(tampered);
    expect(headFromOriginal).not.toBe(headFromTampered);
    const next = mintEnvelope({ name: "noop", args: {} }, "model", headFromOriginal);
    // Dispatcher tracked the tampered head — verify must reject.
    expect(verifyEnvelope(next, headFromTampered)).toEqual({
      ok: false,
      reason: "chain_break",
    });
  });

  it("rejects an envelope whose prevHash does not match the expected chain head", () => {
    const wrongHead = "f".repeat(64);
    const envelope = mintEnvelope({ name: "read", args: {} }, "model", GENESIS_PREV_HASH);
    expect(verifyEnvelope(envelope, wrongHead)).toEqual({ ok: false, reason: "chain_break" });
  });

  it("rejects a missing envelope with envelope_missing reason", () => {
    expect(verifyEnvelope(null, GENESIS_PREV_HASH)).toEqual({
      ok: false,
      reason: "envelope_missing",
    });
    expect(verifyEnvelope(undefined, GENESIS_PREV_HASH)).toEqual({
      ok: false,
      reason: "envelope_missing",
    });
  });

  it("rejects envelopes with malformed shape", () => {
    const base = mintEnvelope({ name: "read", args: {} }, "model", GENESIS_PREV_HASH);
    expect(
      verifyEnvelope({ ...base, nonce: "short" } as VerifiedCmdEnvelope, GENESIS_PREV_HASH),
    ).toEqual({ ok: false, reason: "envelope_shape_invalid_nonce" });
    expect(
      verifyEnvelope(
        { ...base, provenance: "spoofed" as never } as VerifiedCmdEnvelope,
        GENESIS_PREV_HASH,
      ),
    ).toEqual({ ok: false, reason: "envelope_shape_invalid_provenance" });
    expect(
      verifyEnvelope(
        { ...base, call: { name: "", args: {} } } as VerifiedCmdEnvelope,
        GENESIS_PREV_HASH,
      ),
    ).toEqual({ ok: false, reason: "envelope_shape_invalid_name" });
  });

  it("serializes envelopes deterministically regardless of key order", () => {
    const envelope: VerifiedCmdEnvelope = {
      call: { name: "read", args: { b: 2, a: 1 } },
      nonce: "a".repeat(64),
      provenance: "model",
      prevHash: GENESIS_PREV_HASH,
    };
    const reordered: VerifiedCmdEnvelope = {
      prevHash: GENESIS_PREV_HASH,
      provenance: "model",
      nonce: "a".repeat(64),
      call: { args: { a: 1, b: 2 }, name: "read" },
    };
    expect(serializeEnvelope(envelope)).toBe(serializeEnvelope(reordered));
    expect(envelopeHash(envelope)).toBe(envelopeHash(reordered));
  });

  it("mintEnvelope throws on invalid call.name or prevHash", () => {
    expect(() => mintEnvelope({ name: "", args: {} }, "model", GENESIS_PREV_HASH)).toThrow();
    expect(() => mintEnvelope({ name: "read", args: {} }, "model", "tooshort")).toThrow();
  });
});
