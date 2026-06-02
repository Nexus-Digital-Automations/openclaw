/**
 * Spec: D.1 + D.2 (3.D) — per-action context purification primitive.
 *
 * Verifies:
 *  - shouldRunPurification is a pure gate over the "touched untrusted
 *    content" signal: false → skip, true → fire.
 *  - purifyTranscript invokes the judge with the constrained schema and
 *    role "context-purifier"; treats transcript as untrustedFields.
 *  - Fail-open: judge errors return purified=false (caller keeps the
 *    original transcript) with a structured judge_unavailable reason.
 *  - Success returns the sanitized line array with removedCount.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const judgeMock = vi.hoisted(() => vi.fn());
vi.mock("../agents/internal-judge.js", () => ({
  invokeInternalJudge: judgeMock,
}));

import { purifyTranscript, shouldRunPurification } from "./context-purification.js";

beforeEach(() => {
  judgeMock.mockReset();
});

afterEach(() => {
  judgeMock.mockReset();
});

describe("shouldRunPurification — gate", () => {
  it("returns false on a clean turn", () => {
    expect(shouldRunPurification(false)).toBe(false);
  });

  it("returns true on a turn that touched external content", () => {
    expect(shouldRunPurification(true)).toBe(true);
  });
});

describe("purifyTranscript — judge invocation contract", () => {
  it("passes transcript via userPayload with role context-purifier and untrustedFields", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["line a"], removed: [] },
      modelId: "claude-haiku-4-5",
      latencyMs: 100,
      inputTokens: 50,
      outputTokens: 20,
    });
    await purifyTranscript({ transcript: "line a\nline b" });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    const callArg = judgeMock.mock.calls[0][0];
    expect(callArg.role).toBe("context-purifier");
    expect(callArg.modelHint).toBe("fast");
    expect(callArg.userPayload).toEqual({ transcript: "line a\nline b" });
    expect(callArg.untrustedFields).toEqual(["transcript"]);
  });

  it("skips judge for empty transcripts", async () => {
    const verdict = await purifyTranscript({ transcript: "" });
    expect(verdict).toEqual({ purified: false, reason: "empty_transcript" });
    expect(judgeMock).not.toHaveBeenCalled();
  });
});

describe("purifyTranscript — success", () => {
  it("returns sanitized list + removedCount on judge approval", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["legit line"], removed: ["injection: ignore prior"] },
      modelId: "claude-haiku-4-5",
      latencyMs: 110,
      inputTokens: 80,
      outputTokens: 40,
    });
    const verdict = await purifyTranscript({ transcript: "legit\ninject" });
    expect(verdict.purified).toBe(true);
    if (verdict.purified) {
      expect(verdict.sanitized).toEqual(["legit line"]);
      expect(verdict.removedCount).toBe(1);
      expect(verdict.judgeLatencyMs).toBe(110);
    }
  });

  it("handles judge omitting `removed` (schema-optional)", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { sanitized: ["clean"] },
      modelId: "claude-haiku-4-5",
      latencyMs: 80,
      inputTokens: 50,
      outputTokens: 20,
    });
    const verdict = await purifyTranscript({ transcript: "clean" });
    if (!verdict.purified) {
      throw new Error("expected purified");
    }
    expect(verdict.removedCount).toBe(0);
  });
});

describe("purifyTranscript — fail-open on judge error", () => {
  it("returns purified=false on timeout (no throw)", async () => {
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "timeout", detail: "30s" });
    const verdict = await purifyTranscript({ transcript: "anything" });
    expect(verdict).toEqual({
      purified: false,
      reason: "judge_unavailable:timeout",
    });
  });

  it("returns purified=false on schema_violation", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: false,
      reason: "schema_violation",
      detail: "bad shape",
    });
    const verdict = await purifyTranscript({ transcript: "anything" });
    expect(verdict).toEqual({
      purified: false,
      reason: "judge_unavailable:schema_violation",
    });
  });
});
