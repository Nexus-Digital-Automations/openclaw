/**
 * Owner: security/risk-gate.
 *
 * Shared pre-dispatch risk decision point. For the L3 tracer it enforces
 * control-flow integrity: if the run has an approved plan, a tool call matching
 * no approved step is unsanctioned and is blocked. When the run has no plan the
 * gate is a no-op (fails OPEN), so existing flows that never build a plan are
 * unaffected — the gate only bites once a plan is seeded.
 *
 * Default-on, overridable via `OPENCLAW_SECURITY_PLAN_CFI=off`, mirroring the
 * controller-judge flag convention.
 *
 * @internal
 */
import { matchToolCallToPlan } from "./plan-cfi/plan-cfi.js";

const PLAN_CFI_ENV_VAR = "OPENCLAW_SECURITY_PLAN_CFI";

function isPlanCfiEnabled(): boolean {
  const value = process.env[PLAN_CFI_ENV_VAR];
  if (typeof value !== "string") {
    return true;
  }
  const normalized = value.trim().toLowerCase();
  return (
    normalized !== "off" && normalized !== "false" && normalized !== "0" && normalized !== "no"
  );
}

export type RiskVerdict = { block: false } | { block: true; reason: string };

/**
 * Evaluate whether a tool call should be blocked before dispatch. Returns
 * `{block:false}` when CFI is disabled, the run has no plan, or the call matches
 * an approved step; `{block:true}` only when an approved plan exists and the call
 * matches no step (unsanctioned action / control-flow violation).
 */
export function evaluateToolRisk(input: {
  runId: string;
  toolName: string;
  params: unknown;
}): RiskVerdict {
  if (!isPlanCfiEnabled()) {
    return { block: false };
  }
  const match = matchToolCallToPlan(input);
  if (match.matched || match.reason === "no_plan") {
    return { block: false };
  }
  return { block: true, reason: `plan-cfi:${match.reason}:${match.detail}` };
}
