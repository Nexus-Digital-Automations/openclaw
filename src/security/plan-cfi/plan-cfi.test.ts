/**
 * Owner: security/plan-cfi (L3 control-flow integrity).
 *
 * Spec: an approved plan sanctions specific tool calls; the matcher must accept
 * a call only when the tool agrees and every fixed (non-freeParam) constraint
 * holds, and the risk gate must block unsanctioned calls only when a plan exists.
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
  setExternalContentTouchScope,
} from "../../shared/process-external-content-bodies.js";
import { evaluateToolRisk } from "../risk-gate.js";
import { matchToolCallToPlan } from "./plan-cfi.js";
import type { ApprovedPlan, PlanStep } from "./plan-step.types.js";
import { clearApprovedPlansForTests, setApprovedPlan } from "./plan-store.js";

const RUN = "run-1";

// Mark RUN as having ingested untrusted content, the precondition for CFI to
// enforce (before ingestion there is no injection vector, so the gate is open).
function markRunTouchedUntrustedContent(): void {
  setExternalContentTouchScope(RUN);
  recordExternalContentBody("untrusted external body long enough to taint");
  setExternalContentTouchScope(undefined);
}

function plan(steps: PlanStep[]): ApprovedPlan {
  return { planId: "p1", runId: RUN, steps };
}

function step(over: Partial<PlanStep>): PlanStep {
  return {
    stepId: "s1",
    ordinal: 0,
    toolName: "read",
    capability: "read-local",
    paramConstraints: [],
    effectful: false,
    status: "approved",
    ...over,
  };
}

afterEach(() => {
  clearApprovedPlansForTests();
  clearExternalContentBodiesForTests();
});

describe("matchToolCallToPlan", () => {
  it("returns no_plan when the run has no approved plan", () => {
    const verdict = matchToolCallToPlan({ runId: RUN, toolName: "read", params: {} });
    expect(verdict).toEqual({ matched: false, reason: "no_plan", detail: RUN });
  });

  it("matches a call whose tool and pathPrefix constraint are satisfied", () => {
    setApprovedPlan(
      plan([
        step({
          toolName: "read",
          paramConstraints: [
            { kind: "pathPrefix", param: "file_path", allowedPrefixes: ["/work/"] },
          ],
        }),
      ]),
    );
    const verdict = matchToolCallToPlan({
      runId: RUN,
      toolName: "read",
      params: { file_path: "/work/notes.md" },
    });
    expect(verdict).toEqual({ matched: true, stepId: "s1" });
  });

  it("flags no_matching_step when no approved step authorizes the tool", () => {
    setApprovedPlan(plan([step({ toolName: "read" })]));
    const verdict = matchToolCallToPlan({
      runId: RUN,
      toolName: "write",
      params: { content: "x" },
    });
    expect(verdict).toMatchObject({ matched: false, reason: "no_matching_step" });
  });

  it("flags constraint_violation when the tool matches but a fixed param does not", () => {
    setApprovedPlan(
      plan([
        step({
          toolName: "read",
          paramConstraints: [
            { kind: "pathPrefix", param: "file_path", allowedPrefixes: ["/work/"] },
          ],
        }),
      ]),
    );
    const verdict = matchToolCallToPlan({
      runId: RUN,
      toolName: "read",
      params: { file_path: "/etc/passwd" },
    });
    expect(verdict).toMatchObject({ matched: false, reason: "constraint_violation" });
  });

  it("enforces urlHost and lets a freeParam carry any value", () => {
    setApprovedPlan(
      plan([
        step({
          stepId: "fetch",
          toolName: "web_fetch",
          capability: "egress",
          effectful: true,
          paramConstraints: [
            { kind: "urlHost", param: "url", allowedHosts: ["api.example.com"] },
            { kind: "freeParam", param: "note" },
          ],
        }),
      ]),
    );
    expect(
      matchToolCallToPlan({
        runId: RUN,
        toolName: "web_fetch",
        params: { url: "https://api.example.com/x", note: "anything goes here" },
      }),
    ).toEqual({ matched: true, stepId: "fetch" });
    expect(
      matchToolCallToPlan({
        runId: RUN,
        toolName: "web_fetch",
        params: { url: "https://attacker.test/x", note: "anything" },
      }),
    ).toMatchObject({ matched: false, reason: "constraint_violation" });
  });

  it("normalizes tool-name aliases before matching", () => {
    setApprovedPlan(plan([step({ toolName: "exec", capability: "exec" })]));
    expect(
      matchToolCallToPlan({ runId: RUN, toolName: "bash", params: { command: "ls" } }),
    ).toEqual({ matched: true, stepId: "s1" });
  });
});

describe("evaluateToolRisk", () => {
  it("does not block when the run has no plan (gate dormant)", () => {
    expect(evaluateToolRisk({ runId: RUN, toolName: "write", params: {} })).toEqual({
      block: false,
    });
  });

  it("does not block a plan-sanctioned call", () => {
    setApprovedPlan(plan([step({ toolName: "read" })]));
    expect(evaluateToolRisk({ runId: RUN, toolName: "read", params: {} })).toEqual({
      block: false,
    });
  });

  it("does NOT block an unsanctioned call before untrusted content is ingested", () => {
    setApprovedPlan(plan([step({ toolName: "read" })]));
    // No untrusted content touched yet → no injection vector → gate stays open.
    expect(evaluateToolRisk({ runId: RUN, toolName: "exec", params: { command: "rm" } })).toEqual({
      block: false,
    });
  });

  it("blocks an unsanctioned call after untrusted content is ingested", () => {
    setApprovedPlan(plan([step({ toolName: "read" })]));
    markRunTouchedUntrustedContent();
    const verdict = evaluateToolRisk({ runId: RUN, toolName: "exec", params: { command: "rm" } });
    expect(verdict.block).toBe(true);
    if (verdict.block) {
      expect(verdict.reason).toContain("no_matching_step");
    }
  });

  it("is a no-op when disabled via OPENCLAW_SECURITY_PLAN_CFI=off", () => {
    const prev = process.env.OPENCLAW_SECURITY_PLAN_CFI;
    process.env.OPENCLAW_SECURITY_PLAN_CFI = "off";
    try {
      setApprovedPlan(plan([step({ toolName: "read" })]));
      markRunTouchedUntrustedContent(); // would block if enabled; the flag is the only thing opening it
      expect(evaluateToolRisk({ runId: RUN, toolName: "exec", params: {} })).toEqual({
        block: false,
      });
    } finally {
      if (prev === undefined) {
        delete process.env.OPENCLAW_SECURITY_PLAN_CFI;
      } else {
        process.env.OPENCLAW_SECURITY_PLAN_CFI = prev;
      }
    }
  });
});
