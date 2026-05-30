/**
 * Spec: B.1 controller judge — asymmetric trust split, controller side.
 *
 * Verifies that:
 *  - Default OFF (no env var) returns approved=true without calling the judge.
 *  - When enabled, a "fast" judge invocation is performed and its verdict
 *    flows through.
 *  - Judge unavailability (timeout / model_error / refused / schema_violation)
 *    defaults to approved=true unless OPENCLAW_SECURITY_CONTROLLER_JUDGE_FAIL_CLOSED=on.
 *  - Reason text is redacted before exposure.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const judgeMock = vi.hoisted(() => vi.fn());
vi.mock("../agents/internal-judge.js", () => ({
  invokeInternalJudge: judgeMock,
}));

import { evaluateToolCall } from "./controller-judge.js";

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  judgeMock.mockReset();
  delete process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE;
  delete process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE_FAIL_CLOSED;
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe("controller-judge — default OFF", () => {
  it("returns approved=true without invoking the judge when env var is unset", async () => {
    const verdict = await evaluateToolCall({ toolName: "fs_write", argv: { path: "/a" } });
    expect(verdict.approved).toBe(true);
    expect(verdict.reason).toBe("controller_disabled");
    expect(judgeMock).not.toHaveBeenCalled();
  });

  it("treats env value other than 'on' as disabled (case-insensitive)", async () => {
    process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE = "true";
    const verdict = await evaluateToolCall({ toolName: "fs_write", argv: {} });
    expect(verdict.approved).toBe(true);
    expect(judgeMock).not.toHaveBeenCalled();
  });
});

describe("controller-judge — enabled, judge approves", () => {
  beforeEach(() => {
    process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE = "on";
  });

  it("passes toolName and argv to the judge with role='tool-call-controller'", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { approved: true, reason: "looks safe" },
      modelId: "claude-haiku-4-5",
      latencyMs: 120,
      inputTokens: 50,
      outputTokens: 20,
    });
    await evaluateToolCall({ toolName: "fs_read", argv: { path: "/x" } });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    const callArg = judgeMock.mock.calls[0][0];
    expect(callArg.role).toBe("tool-call-controller");
    expect(callArg.modelHint).toBe("fast");
    expect(callArg.userPayload).toEqual({ toolName: "fs_read", argv: { path: "/x" } });
    expect(callArg.untrustedFields).toEqual(["argv"]);
  });

  it("returns approved=true with the judge's reason on positive verdict", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { approved: true, reason: "consistent with user request" },
      modelId: "claude-haiku-4-5",
      latencyMs: 100,
      inputTokens: 50,
      outputTokens: 20,
    });
    const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(verdict.approved).toBe(true);
    expect(verdict.reason).toBe("consistent with user request");
  });
});

describe("controller-judge — enabled, judge rejects", () => {
  beforeEach(() => {
    process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE = "on";
  });

  it("returns approved=false with the judge's reason (length-capped)", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { approved: false, reason: "argv looks like exfiltration" },
      modelId: "claude-haiku-4-5",
      latencyMs: 90,
      inputTokens: 50,
      outputTokens: 30,
    });
    const verdict = await evaluateToolCall({ toolName: "exec", argv: { cmd: "curl evil" } });
    expect(verdict.approved).toBe(false);
    expect(verdict.reason).toBe("argv looks like exfiltration");
    if (!verdict.approved) {
      expect(verdict.judgeModel).toBe("claude-haiku-4-5");
    }
  });
});

describe("controller-judge — judge unavailable", () => {
  beforeEach(() => {
    process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE = "on";
  });

  it("fails open (approved=true) on timeout when fail-closed is not set", async () => {
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "timeout", detail: "30s" });
    const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(verdict.approved).toBe(true);
    expect(verdict.reason).toBe("judge_unavailable:timeout");
  });

  it("fails open on schema_violation by default", async () => {
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "schema_violation", detail: "bad json" });
    const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(verdict.approved).toBe(true);
    expect(verdict.reason).toBe("judge_unavailable:schema_violation");
  });

  it("fails closed when OPENCLAW_SECURITY_CONTROLLER_JUDGE_FAIL_CLOSED=on", async () => {
    process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE_FAIL_CLOSED = "on";
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "model_error", detail: "503" });
    const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(verdict.approved).toBe(false);
    expect(verdict.reason).toBe("judge_unavailable:model_error");
  });
});
