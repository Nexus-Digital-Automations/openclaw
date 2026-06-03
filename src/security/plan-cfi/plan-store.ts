/**
 * Owner: security/plan-cfi (L3 control-flow integrity).
 *
 * Process-local store of each run's approved plan, keyed by runId. Run-scoped so
 * concurrent runs never clobber each other (distinct keys). In-memory only for
 * the tracer; a plan lives for the duration of a run and is dropped on restart.
 * Durable persistence is intentionally deferred — a lost plan fails OPEN (the
 * CFI gate is a no-op when no plan exists), never closed, so a restart cannot
 * brick an in-flight run.
 *
 * @internal
 */
import type { ApprovedPlan } from "./plan-step.types.js";

const plansByRunId = new Map<string, ApprovedPlan>();

export function getApprovedPlan(runId: string): ApprovedPlan | undefined {
  return plansByRunId.get(runId);
}

export function setApprovedPlan(plan: ApprovedPlan): void {
  plansByRunId.set(plan.runId, plan);
}

export function deleteApprovedPlan(runId: string): void {
  plansByRunId.delete(runId);
}

/**
 * Reset for tests. Production callers must not use this.
 *
 * @internal
 */
export function clearApprovedPlansForTests(): void {
  plansByRunId.clear();
}
