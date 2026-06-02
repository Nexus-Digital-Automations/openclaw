/**
 * Spec: B.1 controller judge — asymmetric trust split, controller side.
 *
 * Verifies the **default-on, fail-closed** semantics:
 *  - Unset env → judge fires (controller is enabled by default).
 *  - Explicit opt-out tokens (off/false/0/no) → judge is bypassed.
 *  - Judge unavailability → approved=false by default (fail-closed).
 *  - Explicit fail-open opt-out → judge errors degrade to approved=true.
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

describe("controller-judge — default ON", () => {
  it("invokes the judge when no env var is set", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { approved: true, reason: "ok" },
      modelId: "claude-haiku-4-5",
      latencyMs: 100,
      inputTokens: 50,
      outputTokens: 20,
    });
    const verdict = await evaluateToolCall({ toolName: "fs_write", argv: { path: "/a" } });
    expect(judgeMock).toHaveBeenCalledTimes(1);
    expect(verdict.approved).toBe(true);
  });

  it("still invokes the judge when env var is set to 'on' (legacy compat)", async () => {
    process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE = "on";
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { approved: true },
      modelId: "claude-haiku-4-5",
      latencyMs: 100,
      inputTokens: 50,
      outputTokens: 20,
    });
    await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(judgeMock).toHaveBeenCalledTimes(1);
  });
});

describe("controller-judge — explicit opt-out", () => {
  it.each(["off", "false", "0", "no", "OFF", "FALSE"])(
    "bypasses the judge when env value is %s",
    async (value) => {
      process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE = value;
      const verdict = await evaluateToolCall({ toolName: "fs_write", argv: {} });
      expect(judgeMock).not.toHaveBeenCalled();
      expect(verdict.approved).toBe(true);
      expect(verdict.reason).toBe("controller_disabled");
    },
  );
});

describe("controller-judge — judge approves / rejects", () => {
  it("passes toolName + argv with role='tool-call-controller' and untrustedFields", async () => {
    judgeMock.mockResolvedValueOnce({
      ok: true,
      output: { approved: true, reason: "looks safe" },
      modelId: "claude-haiku-4-5",
      latencyMs: 120,
      inputTokens: 50,
      outputTokens: 20,
    });
    await evaluateToolCall({ toolName: "fs_read", argv: { path: "/x" } });
    const callArg = judgeMock.mock.calls[0][0];
    expect(callArg.role).toBe("tool-call-controller");
    expect(callArg.modelHint).toBe("fast");
    expect(callArg.userPayload).toEqual({ toolName: "fs_read", argv: { path: "/x" } });
    // I2: toolName is model-proposed and must also be marked untrusted so it
    // never reaches the judge's trusted section unsanitized.
    expect(callArg.untrustedFields).toEqual(["argv", "toolName"]);
  });

  it("returns approved=false with the judge's reason on negative verdict", async () => {
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

describe("controller-judge — judge throws", () => {
  // I1: a synchronous throw from the judge must become a fail-closed verdict,
  // self-enforcing the documented "never throws" contract.
  it("fails CLOSED when the judge invocation throws", async () => {
    judgeMock.mockRejectedValueOnce(new Error("provider init failed"));
    const verdict = await evaluateToolCall({ toolName: "exec", argv: { cmd: "x" } });
    expect(verdict.approved).toBe(false);
    expect(verdict.reason).toBe("judge_unavailable:exception");
  });
});

describe("controller-judge — judge unavailable", () => {
  it("fails CLOSED by default on timeout (judge unavailability blocks dispatch)", async () => {
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "timeout", detail: "30s" });
    const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(verdict.approved).toBe(false);
    expect(verdict.reason).toBe("judge_unavailable:timeout");
  });

  it("fails CLOSED by default on schema_violation", async () => {
    judgeMock.mockResolvedValueOnce({ ok: false, reason: "schema_violation", detail: "bad json" });
    const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
    expect(verdict.approved).toBe(false);
    expect(verdict.reason).toBe("judge_unavailable:schema_violation");
  });

  it.each(["off", "false", "0", "no"])(
    "fails OPEN when OPENCLAW_SECURITY_CONTROLLER_JUDGE_FAIL_CLOSED=%s (opt-out)",
    async (value) => {
      process.env.OPENCLAW_SECURITY_CONTROLLER_JUDGE_FAIL_CLOSED = value;
      judgeMock.mockResolvedValueOnce({ ok: false, reason: "model_error", detail: "503" });
      const verdict = await evaluateToolCall({ toolName: "fs_read", argv: {} });
      expect(verdict.approved).toBe(true);
      expect(verdict.reason).toBe("judge_unavailable:model_error");
    },
  );
});
