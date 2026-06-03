/**
 * Owner: security/plan-cfi (L3 control-flow integrity).
 *
 * A run's approved plan is the set of tool-call steps sanctioned BEFORE the agent
 * ingests untrusted content. The CFI gate rejects any tool call that does not
 * match an approved step, so prompt injection can fill the parameters of an
 * approved step but can never add a step or redirect control flow.
 *
 * @internal
 */

/**
 * A bound on one parameter of an approved step. Non-`freeParam` constraints are
 * the control-flow surface (which tool, which target) the planner fixes;
 * `freeParam` marks a slot the planner intentionally leaves open for (possibly
 * untrusted) data to fill.
 */
export type ParamConstraint =
  | { kind: "pathPrefix"; param: string; allowedPrefixes: readonly string[] }
  | { kind: "enum"; param: string; allowed: readonly string[] }
  | { kind: "urlHost"; param: string; allowedHosts: readonly string[] }
  | { kind: "freeParam"; param: string };

/** One sanctioned tool call in a run's approved plan. */
export interface PlanStep {
  stepId: string;
  ordinal: number;
  /** Exact tool name this step authorizes (post-normalizeToolName). */
  toolName: string;
  /** Capability tag, shared with the L1 capability gate vocabulary. */
  capability: string;
  paramConstraints: readonly ParamConstraint[];
  /** Whether executing this step mutates state or exfiltrates (gates taint-flow approval in L3 Phase 6). */
  effectful: boolean;
  status: "approved" | "consumed" | "revoked";
}

/** The approved plan for a single agent run, keyed by runId. */
export interface ApprovedPlan {
  planId: string;
  runId: string;
  steps: PlanStep[];
  /** Set the instant the run first ingests untrusted content; after this, adding a step needs approval. */
  frozenAt?: number;
}

/** Result of matching a tool call against a run's approved plan. */
export type PlanMatchVerdict =
  | { matched: true; stepId: string }
  | {
      matched: false;
      reason: "no_plan" | "no_matching_step" | "constraint_violation";
      detail: string;
    };
