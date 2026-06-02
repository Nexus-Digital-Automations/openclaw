// Owner: plugins/builtin-security-sandwich.
//
// Built-in security-sandwich plugin (Phase 2.C of the security blueprint).
// Wires three pi-agent-core hooks against the contract pinned by
// `src/plugins/security-sandwich-hook-surface.test.ts`:
//
//   - before_prompt_build  → prepend the sandwich-pattern reminder so the
//                            operator's policy bookends every model turn
//   - before_tool_call     → block dispatch when the upstream output firewall
//                            (P0.1) has flipped this turn's trip flag (stub:
//                            no-op until P0.1 lands a flag source)
//   - message_sending      → cancel + redact when outbound text leaks an
//                            unredacted secret literal or external-content
//                            canary
//
// Always-on by design: this is a default security layer, not a configurable
// add-on. The plugin must remain default-on per the blueprint acceptance
// criterion ("disabling the plugin restores legacy behavior" is operational
// proof, not a knob the agent path should consult per-turn).

import type {
  PluginHookBeforePromptBuildResult,
  PluginHookBeforeToolCallResult,
  PluginHookHandlerMap,
  PluginHookMessageSendingResult,
} from "../hook-types.js";
import { scanOutboundContent } from "./outbound-redaction.js";
import { getSecuritySandwichPromptAnchor } from "./system-prompt-anchor.js";

// Narrow subscriber surface we need from the plugin API. The full
// OpenClawPluginApi shape lives behind `openclaw/plugin-sdk/plugin-entry`;
// the locked hook-surface test pins the same `on(name, handler)` interface,
// so we re-state only that fragment to keep this module loader-agnostic
// (the loader registration is followup work — see SECURITY_SANDWICH_FOLLOWUPS).
export type SecuritySandwichApi = {
  on<TName extends keyof PluginHookHandlerMap>(
    name: TName,
    handler: PluginHookHandlerMap[TName],
  ): void;
};

export const SECURITY_SANDWICH_PLUGIN_ID = "openclaw-security-sandwich";

/**
 * Register the three sandwich hooks on the supplied plugin API.
 *
 * Failure modes: never throws synchronously. Each handler returns a void
 * decision when no action is needed so the hook runner falls through to the
 * next handler unchanged.
 *
 * @stable
 */
export function registerSecuritySandwichPlugin(api: SecuritySandwichApi): void {
  api.on("before_prompt_build", buildPromptSandwich);
  api.on("before_tool_call", evaluateToolCallTrip);
  api.on("message_sending", redactOutboundMessage);
}

function buildPromptSandwich(): PluginHookBeforePromptBuildResult {
  return {
    prependSystemContext: getSecuritySandwichPromptAnchor(),
  };
}

// Stub for the P0.1 output-firewall integration. Once P0.1 lands a
// per-turn trip flag in the hook event context, this reads it and returns
// `{ block: true, blockReason }`. Until then the hook is a no-op so the
// plugin can ship without a hard dependency on unlanded primitives.
function evaluateToolCallTrip(): PluginHookBeforeToolCallResult | void {
  return undefined;
}

function redactOutboundMessage(event: { content: string }): PluginHookMessageSendingResult | void {
  const scan = scanOutboundContent(event.content);
  if (scan.safe) {
    return undefined;
  }
  return {
    cancel: true,
    cancelReason: scan.reason,
    content: scan.redacted,
  };
}

// Tracked followups (not landing in P0.4):
//   - loader auto-registration: wire registerSecuritySandwichPlugin into the
//     bundled plugin registration path. Today the module is callable but not
//     auto-loaded; a follow-up will add the loader entry once the
//     in-`src/plugins` vs `extensions/` boundary question is resolved with
//     a maintainer review.
//   - before_tool_call firewall trip flag: replace the no-op stub with a
//     real read once P0.1 ships the turn-level trip flag.
//   - ≥80% unsafe-dispatch reduction acceptance: requires P0.1 (output
//     firewall) plus a real model in the loop; the corpus test in this
//     change covers deterministic plugin-side block-or-mask behavior.
export const SECURITY_SANDWICH_FOLLOWUPS = [
  "loader-auto-registration",
  "before-tool-call-firewall-trip-flag",
  "end-to-end-eighty-percent-reduction-acceptance",
] as const;
