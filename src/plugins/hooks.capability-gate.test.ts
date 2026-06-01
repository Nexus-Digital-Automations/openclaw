/**
 * Owner: plugins/hooks.capability-gate.test
 *
 * Spec: C.3 — warn-mode capability gate at runVoidHook dispatch.
 *
 * Invariants asserted as specs (test names):
 *  - Hooks outside the declared surface bypass the gate (no telemetry)
 *  - Plugins without registered capabilities are grandfathered
 *  - Plugin declaring the hook proceeds without telemetry
 *  - Plugin declaring a different hook emits warn + counter increment
 *  - Counter key includes the seam label so audit consumers can slice
 *  - Audit payload carries the seam field for the same reason
 *  - Newly-gated behavior hooks (e.g. before_compaction) emit on miss
 *  - DECLARED_HOOK_NAMES exactly matches capabilities.ts PluginHookName set
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearPluginCapabilitiesForTests,
  DECLARED_PLUGIN_HOOK_NAMES,
  setPluginCapabilities,
  setPluginCapabilityEnforcement,
} from "./capabilities.js";
import {
  CapabilityDeniedError,
  createHookRunner,
  passesCapabilityGateOrWarnForTests,
  resetCapabilityViolationsForTests,
  snapshotCapabilityViolationsForTests,
} from "./hooks.js";
import { addStaticTestHooks } from "./hooks.test-helpers.js";
import { createEmptyPluginRegistry } from "./registry.js";
import type { PluginHookBeforeToolCallResult, PluginHookToolContext } from "./types.js";

const PLUGIN_ID = "plugin-under-test";

beforeEach(() => {
  clearPluginCapabilitiesForTests();
  resetCapabilityViolationsForTests();
});

afterEach(() => {
  clearPluginCapabilitiesForTests();
  resetCapabilityViolationsForTests();
});

describe("passesCapabilityGateOrWarn — declared surface boundary", () => {
  it("returns true without telemetry when hookName is outside the declared surface", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    const warn = vi.fn();
    const allowed = passesCapabilityGateOrWarnForTests(
      PLUGIN_ID,
      "tool_result_persist",
      { warn },
      { seam: "runVoidHook" },
    );
    expect(allowed).toBe(true);
    expect(warn).not.toHaveBeenCalled();
    expect(snapshotCapabilityViolationsForTests().size).toBe(0);
  });

  it("grandfathers plugins with no registered capabilities", () => {
    const warn = vi.fn();
    const allowed = passesCapabilityGateOrWarnForTests(
      "plugin-no-manifest",
      "before_tool_call",
      { warn },
      { seam: "runVoidHook" },
    );
    expect(allowed).toBe(true);
    expect(warn).not.toHaveBeenCalled();
    expect(snapshotCapabilityViolationsForTests().size).toBe(0);
  });
});

describe("passesCapabilityGateOrWarn — declared-hook match", () => {
  it("passes silently when the plugin declared the hook", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_tool_call"] });
    const warn = vi.fn();
    const allowed = passesCapabilityGateOrWarnForTests(
      PLUGIN_ID,
      "before_tool_call",
      { warn },
      { seam: "runVoidHook" },
    );
    expect(allowed).toBe(true);
    expect(warn).not.toHaveBeenCalled();
    expect(snapshotCapabilityViolationsForTests().size).toBe(0);
  });

  it("throws CapabilityDeniedError + emits warn + records counter when an enforced plugin's hook is undeclared", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "before_tool_call",
        { warn },
        { seam: "runVoidHook" },
      ),
    ).toThrow(CapabilityDeniedError);
    expect(warn).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(warn.mock.calls[0][0]);
    expect(payload.event).toBe("plugin.capability.violation_blocked");
    expect(payload.pluginId).toBe(PLUGIN_ID);
    expect(payload.hookName).toBe("before_tool_call");
    expect(payload.seam).toBe("runVoidHook");
    expect(payload.declared).toEqual(["before_prompt_build"]);
  });
});

describe("passesCapabilityGateOrWarn — per-seam telemetry", () => {
  it("composes the counter key from pluginId::hookName::seam (throw still records)", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "before_tool_call",
        { warn },
        { seam: "runVoidHook" },
      ),
    ).toThrow(CapabilityDeniedError);
    const counters = snapshotCapabilityViolationsForTests();
    expect(counters.get(`${PLUGIN_ID}::before_tool_call::runVoidHook`)).toBe(1);
  });

  it("defaults the seam label to runVoidHook when omitted", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(PLUGIN_ID, "before_tool_call", { warn }),
    ).toThrow(CapabilityDeniedError);
    const counters = snapshotCapabilityViolationsForTests();
    expect(counters.get(`${PLUGIN_ID}::before_tool_call::runVoidHook`)).toBe(1);
    const payload = JSON.parse(warn.mock.calls[0][0]);
    expect(payload.seam).toBe("runVoidHook");
  });

  it("tracks distinct counter keys per seam for the same hook violation", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "before_tool_call",
        { warn },
        { seam: "runVoidHook" },
      ),
    ).toThrow(CapabilityDeniedError);
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "before_tool_call",
        { warn },
        { seam: "runClaimingHooksList" },
      ),
    ).toThrow(CapabilityDeniedError);
    const counters = snapshotCapabilityViolationsForTests();
    expect(counters.get(`${PLUGIN_ID}::before_tool_call::runVoidHook`)).toBe(1);
    expect(counters.get(`${PLUGIN_ID}::before_tool_call::runClaimingHooksList`)).toBe(1);
  });
});

describe("passesCapabilityGateOrWarn — enforced mode (F.4 hard-block)", () => {
  it("blocks an enforced plugin's undeclared hook: throws CapabilityDeniedError, logs violation_blocked", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "before_tool_call",
        { warn },
        { seam: "runVoidHook" },
      ),
    ).toThrow(CapabilityDeniedError);
    const payload = JSON.parse(warn.mock.calls[0][0]);
    expect(payload.event).toBe("plugin.capability.violation_blocked");
    expect(payload.pluginId).toBe(PLUGIN_ID);
  });

  it("warns but allows a grandfathered plugin's undeclared hook: returns true", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "grandfathered");
    const warn = vi.fn();
    const allowed = passesCapabilityGateOrWarnForTests(
      PLUGIN_ID,
      "before_tool_call",
      { warn },
      { seam: "runVoidHook" },
    );
    expect(allowed).toBe(true);
    const payload = JSON.parse(warn.mock.calls[0][0]);
    expect(payload.event).toBe("plugin.capability.violation_observed");
  });

  it("still allows an enforced plugin's declared hook without telemetry", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_tool_call"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    const allowed = passesCapabilityGateOrWarnForTests(
      PLUGIN_ID,
      "before_tool_call",
      { warn },
      { seam: "runVoidHook" },
    );
    expect(allowed).toBe(true);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("passesCapabilityGateOrWarn — expanded behavior-hook surface", () => {
  it("throws when an enforced manifest excludes before_compaction (newly gated in C.3.c2)", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["before_prompt_build"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "before_compaction",
        { warn },
        { seam: "runVoidHook" },
      ),
    ).toThrow(CapabilityDeniedError);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(
      snapshotCapabilityViolationsForTests().get(`${PLUGIN_ID}::before_compaction::runVoidHook`),
    ).toBe(1);
  });

  it("throws when an enforced manifest excludes llm_input", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["session_start"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(PLUGIN_ID, "llm_input", { warn }, { seam: "runVoidHook" }),
    ).toThrow(CapabilityDeniedError);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("throws when an enforced manifest excludes message_sent", () => {
    setPluginCapabilities(PLUGIN_ID, { hooks: ["session_end"] });
    setPluginCapabilityEnforcement(PLUGIN_ID, "enforced");
    const warn = vi.fn();
    expect(() =>
      passesCapabilityGateOrWarnForTests(
        PLUGIN_ID,
        "message_sent",
        { warn },
        { seam: "runVoidHook" },
      ),
    ).toThrow(CapabilityDeniedError);
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe("DECLARED_PLUGIN_HOOK_NAMES — surface lock", () => {
  it("contains exactly the hooks the C.3 plan locks into the gated surface", () => {
    const expected = new Set<string>([
      "before_prompt_build",
      "before_tool_call",
      "message_sending",
      "post_tool_result",
      "post_message_send",
      "session_start",
      "session_end",
      "before_compaction",
      "after_compaction",
      "before_reset",
      "message_received",
      "message_sent",
      "after_tool_call",
      "agent_end",
      "llm_input",
      "llm_output",
      "model_call_started",
      "model_call_ended",
      "subagent_spawned",
      "subagent_ended",
      "cron_changed",
    ]);
    expect(new Set(DECLARED_PLUGIN_HOOK_NAMES)).toEqual(expected);
  });
});

// Integration: prove the F.4 hard-block reaches the modifying-hook DISPATCH
// loop, not just the gate function. before_tool_call is declared-surface and
// dispatched via runModifyingHook, so an enforced plugin that violates its
// declared surface must have its result dropped (handler skipped), while a
// grandfathered one still merges (warn-only).
describe("runModifyingHook dispatch — enforced hard-block", () => {
  const stubToolCtx: PluginHookToolContext = {
    toolName: "bash",
    agentId: "main",
    sessionKey: "agent:main:main",
  };

  function runBeforeToolCallFor(
    pluginId: string,
  ): Promise<PluginHookBeforeToolCallResult | undefined> {
    const registry = createEmptyPluginRegistry();
    addStaticTestHooks<PluginHookBeforeToolCallResult>(registry, {
      hookName: "before_tool_call",
      hooks: [{ pluginId, result: { block: true, blockReason: "blocked-by-handler" } }],
    });
    const runner = createHookRunner(registry, { logger: { warn: vi.fn(), debug: vi.fn() } });
    return runner.runBeforeToolCall({ toolName: "bash", params: {} }, stubToolCtx);
  }

  it("drops an enforced plugin's undeclared modifying-hook result", async () => {
    // Declares a DIFFERENT hook, so before_tool_call is a violation.
    setPluginCapabilities("enforced-mod-plugin", { hooks: ["session_start"] });
    setPluginCapabilityEnforcement("enforced-mod-plugin", "enforced");

    const result = await runBeforeToolCallFor("enforced-mod-plugin");

    expect(result?.block).toBeUndefined();
    expect(
      snapshotCapabilityViolationsForTests().get(
        "enforced-mod-plugin::before_tool_call::runModifyingHook",
      ),
    ).toBe(1);
  });

  it("still merges a grandfathered plugin's undeclared modifying-hook result", async () => {
    setPluginCapabilities("grandfathered-mod-plugin", { hooks: ["session_start"] });
    setPluginCapabilityEnforcement("grandfathered-mod-plugin", "grandfathered");

    const result = await runBeforeToolCallFor("grandfathered-mod-plugin");

    expect(result?.block).toBe(true);
    expect(result?.blockReason).toBe("blocked-by-handler");
  });
});
