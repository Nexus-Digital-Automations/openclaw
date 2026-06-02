// Owner: agents/security. Spec tests for the external-content canary gate in
// runBeforeToolCallHook (P0.3). When a tool's argv contains a body literal
// that recordExternalContentBody() previously tainted, the hook must force the
// operator-approval path with the matched canary surfaced for UI display.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetDiagnosticEventsForTest } from "../infra/diagnostic-events.js";
import { resetDiagnosticSessionStateForTest } from "../logging/diagnostic-session-state.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
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

  it("does NOT fire the gate on non-exec tools even when params contain a tainted body", async () => {
    recordExternalContentBody(TAINTED_BODY_A);

    const outcome = await runBeforeToolCallHook({
      toolName: "read_file",
      params: { file_path: `/notes/${TAINTED_BODY_A}.md` },
      ctx: { agentId: "main", sessionKey: "main" },
    });

    expect(outcome.blocked).toBe(false);
    expect(mockCallGateway).not.toHaveBeenCalled();
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
});
