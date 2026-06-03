/**
 * Owner: security/plan-cfi (L3 control-flow integrity).
 *
 * Matches a tool call against the run's approved plan. A call matches a step iff
 * the tool name agrees AND every non-`freeParam` constraint holds — so untrusted
 * data can only ever fill the `freeParam` slots the planner left open, never add
 * a step or steer the call to a different tool/target.
 *
 * @internal
 */
import { normalizeToolName } from "../../agents/tool-policy-shared.js";
import type { ParamConstraint, PlanMatchVerdict, PlanStep } from "./plan-step.types.js";
import { getApprovedPlan } from "./plan-store.js";

function readParam(params: unknown, name: string): unknown {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    return undefined;
  }
  return (params as Record<string, unknown>)[name];
}

function constraintSatisfied(constraint: ParamConstraint, params: unknown): boolean {
  if (constraint.kind === "freeParam") {
    return true;
  }
  const value = readParam(params, constraint.param);
  if (typeof value !== "string") {
    return false;
  }
  if (constraint.kind === "pathPrefix") {
    return constraint.allowedPrefixes.some((prefix) => value.startsWith(prefix));
  }
  if (constraint.kind === "enum") {
    return constraint.allowed.includes(value);
  }
  // urlHost: an unparseable URL never satisfies a host constraint.
  try {
    return constraint.allowedHosts.includes(new URL(value).host);
  } catch {
    return false;
  }
}

function stepMatches(step: PlanStep, toolName: string, params: unknown): boolean {
  return (
    step.status === "approved" &&
    normalizeToolName(step.toolName) === toolName &&
    step.paramConstraints.every((constraint) => constraintSatisfied(constraint, params))
  );
}

/**
 * Decide whether a tool call is sanctioned by the run's approved plan. Returns
 * `no_plan` (gate dormant) when the run has no plan; `no_matching_step` when no
 * approved step authorizes this tool; `constraint_violation` when a step's tool
 * matches but its fixed parameters do not.
 */
export function matchToolCallToPlan(input: {
  runId: string;
  toolName: string;
  params: unknown;
}): PlanMatchVerdict {
  const plan = getApprovedPlan(input.runId);
  if (!plan) {
    return { matched: false, reason: "no_plan", detail: input.runId };
  }
  const toolName = normalizeToolName(input.toolName);
  const match = plan.steps.find((step) => stepMatches(step, toolName, input.params));
  if (match) {
    return { matched: true, stepId: match.stepId };
  }
  // Distinguish "wrong tool entirely" from "right tool, fixed param violated" so
  // the gate message and any later approval can explain the actual breach.
  const toolNameMatched = plan.steps.some(
    (step) => step.status === "approved" && normalizeToolName(step.toolName) === toolName,
  );
  return toolNameMatched
    ? { matched: false, reason: "constraint_violation", detail: toolName }
    : { matched: false, reason: "no_matching_step", detail: toolName };
}
