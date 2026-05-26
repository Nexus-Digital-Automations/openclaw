/**
 * Owner: plugins/security-sandwich-hook-surface.
 *
 * Regression guard for the future "security-sandwich" plugin (deferred
 * Phase 2.C of `specs/security-blueprint-full.md`). That plugin will register
 * mutation/abort handlers on three pi-agent-core hooks:
 *   - `before_prompt_build` (mutates outgoing system prompt)
 *   - `before_tool_call`    (blocks dispatch / requires approval)
 *   - `message_sending`     (cancels send / rewrites content)
 *
 * If any of those hook names is renamed in the SDK, or if their result
 * contract weakens below "mutation + abort", this test fails so the gap
 * surfaces before the plugin gets built. No production behavior here — pure
 * type + name surface lock.
 */
import { registerHookHandlersForTest } from "openclaw/plugin-sdk/channel-test-helpers";
import { describe, expect, it } from "vitest";
import type { PluginHookBeforePromptBuildResult } from "./hook-before-agent-start.types.js";
import type { PluginHookMessageSendingResult } from "./hook-message.types.js";
import {
  PLUGIN_HOOK_NAMES,
  type PluginHookBeforeToolCallResult,
  type PluginHookHandlerMap,
} from "./hook-types.js";

const SECURITY_SANDWICH_REQUIRED_HOOKS = [
  "before_prompt_build",
  "before_tool_call",
  "message_sending",
] as const satisfies readonly (keyof PluginHookHandlerMap)[];

type SecuritySandwichApi = {
  on<TName extends keyof PluginHookHandlerMap>(
    name: TName,
    handler: PluginHookHandlerMap[TName],
  ): void;
};

describe("security-sandwich hook surface", () => {
  it("keeps the three required hook names listed in PLUGIN_HOOK_NAMES", () => {
    for (const name of SECURITY_SANDWICH_REQUIRED_HOOKS) {
      expect(PLUGIN_HOOK_NAMES).toContain(name);
    }
  });

  it("accepts a no-op handler registration on each required hook via the SDK test harness", () => {
    const handlers = registerHookHandlersForTest<SecuritySandwichApi>({
      config: {},
      register: (api) => {
        api.on("before_prompt_build", () => undefined);
        api.on("before_tool_call", () => undefined);
        api.on("message_sending", () => undefined);
      },
    });
    for (const name of SECURITY_SANDWICH_REQUIRED_HOOKS) {
      expect(handlers.get(name)).toBeTypeOf("function");
    }
  });

  it("permits a prompt-mutating result shape on before_prompt_build", () => {
    const handler: PluginHookHandlerMap["before_prompt_build"] = () =>
      ({
        systemPrompt: "sandwich-mutated",
        prependSystemContext: "policy",
      }) satisfies PluginHookBeforePromptBuildResult;
    expect(handler).toBeTypeOf("function");
  });

  it("permits a block + reason result shape on before_tool_call", () => {
    const handler: PluginHookHandlerMap["before_tool_call"] = () =>
      ({
        block: true,
        blockReason: "external-content taint",
      }) satisfies PluginHookBeforeToolCallResult;
    expect(handler).toBeTypeOf("function");
  });

  it("permits a cancel + content-rewrite result shape on message_sending", () => {
    const handler: PluginHookHandlerMap["message_sending"] = () =>
      ({
        cancel: true,
        cancelReason: "redaction policy",
        content: "«REDACTED»",
      }) satisfies PluginHookMessageSendingResult;
    expect(handler).toBeTypeOf("function");
  });
});
