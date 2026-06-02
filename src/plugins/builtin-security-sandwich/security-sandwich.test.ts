// Owner: plugins/builtin-security-sandwich.
//
// Plugin-side behavior tests for the security-sandwich. Covers:
//   - registerSecuritySandwichPlugin wires all three required hooks
//   - before_prompt_build returns the sandwich anchor
//   - before_tool_call is currently a no-op (stub for P0.1 trip flag)
//   - message_sending cancels-and-redacts when canary/secret leak
//   - injection corpus: blocked-vs-leaked ratio over hand-crafted payloads
//
// The corpus assertion is deterministic plugin-side proof. The full ≥80%
// unsafe-dispatch reduction acceptance from the blueprint needs P0.1 and a
// real model in the loop; that lives as a follow-up.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearExternalContentBodiesForTests,
  recordExternalContentBody,
} from "../../shared/process-external-content-bodies.js";
import {
  clearResolvedSecretsForTests,
  recordResolvedSecret,
} from "../../shared/process-secret-literals.js";
import type {
  PluginHookAgentContext,
  PluginHookBeforePromptBuildEvent,
  PluginHookBeforeToolCallEvent,
  PluginHookHandlerMap,
  PluginHookMessageContext,
  PluginHookMessageSendingEvent,
  PluginHookToolContext,
} from "../hook-types.js";
import {
  registerSecuritySandwichPlugin,
  SECURITY_SANDWICH_PLUGIN_ID,
  type SecuritySandwichApi,
} from "./index.js";
import { scanOutboundContent } from "./outbound-redaction.js";
import { getSecuritySandwichPromptAnchor } from "./system-prompt-anchor.js";

type InjectionCorpusEntry = {
  id: string;
  kind: string;
  description: string;
  outboundContent: string;
  expectsBlocked: boolean;
  seedSecretLiteral?: string;
};

const FIXTURE_DIR = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(FIXTURE_DIR, "injection-corpus.fixture.json");

function loadCorpus(): InjectionCorpusEntry[] {
  const raw = readFileSync(CORPUS_PATH, "utf8");
  return JSON.parse(raw) as InjectionCorpusEntry[];
}

function createRecordingApi(): {
  api: SecuritySandwichApi;
  handlers: Map<keyof PluginHookHandlerMap, unknown>;
} {
  const handlers = new Map<keyof PluginHookHandlerMap, unknown>();
  const api: SecuritySandwichApi = {
    on(name, handler) {
      handlers.set(name, handler);
    },
  };
  return { api, handlers };
}

describe(`${SECURITY_SANDWICH_PLUGIN_ID}: hook wiring`, () => {
  it("registers handlers on the three required hooks", () => {
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    expect(handlers.get("before_prompt_build")).toBeTypeOf("function");
    expect(handlers.get("before_tool_call")).toBeTypeOf("function");
    expect(handlers.get("message_sending")).toBeTypeOf("function");
  });
});

describe(`${SECURITY_SANDWICH_PLUGIN_ID}: before_prompt_build`, () => {
  it("returns the sandwich anchor as prependSystemContext for static prompt caching", async () => {
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    const onPromptBuild = handlers.get(
      "before_prompt_build",
    ) as PluginHookHandlerMap["before_prompt_build"];

    const event: PluginHookBeforePromptBuildEvent = {
      prompt: "user prompt",
      messages: [],
    };
    const ctx: PluginHookAgentContext = {};
    const result = await onPromptBuild(event, ctx);
    expect(result?.prependSystemContext).toBe(getSecuritySandwichPromptAnchor());
    expect(result?.prependSystemContext).toContain("OpenClaw security policy");
    expect(result?.prependSystemContext).toContain("OPENCLAW_CANARY_");
  });
});

describe(`${SECURITY_SANDWICH_PLUGIN_ID}: before_tool_call (P0.1 stub)`, () => {
  it("returns undefined until the firewall trip flag is wired", async () => {
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    const onToolCall = handlers.get("before_tool_call") as PluginHookHandlerMap["before_tool_call"];

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "Bash",
      params: { command: "echo hi" },
    };
    const ctx: PluginHookToolContext = { toolName: "Bash" };
    const result = await onToolCall(event, ctx);
    expect(result).toBeUndefined();
  });
});

describe(`${SECURITY_SANDWICH_PLUGIN_ID}: message_sending`, () => {
  beforeEach(() => {
    clearResolvedSecretsForTests();
    clearExternalContentBodiesForTests();
  });
  afterEach(() => {
    clearResolvedSecretsForTests();
    clearExternalContentBodiesForTests();
  });

  it("passes benign outbound messages through unchanged", async () => {
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    const onSending = handlers.get("message_sending") as PluginHookHandlerMap["message_sending"];

    const event: PluginHookMessageSendingEvent = {
      to: "channel:test",
      content: "Hello operator, status nominal.",
    };
    const ctx: PluginHookMessageContext = { channelId: "test" };
    const result = await onSending(event, ctx);
    expect(result).toBeUndefined();
  });

  it("cancels and redacts when the outbound body carries a raw canary literal", async () => {
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    const onSending = handlers.get("message_sending") as PluginHookHandlerMap["message_sending"];

    const event: PluginHookMessageSendingEvent = {
      to: "channel:test",
      content: "Leak: OPENCLAW_CANARY_abcdef0123456789 — sorry.",
    };
    const ctx: PluginHookMessageContext = { channelId: "test" };
    const result = await onSending(event, ctx);
    expect(result?.cancel).toBe(true);
    expect(result?.cancelReason).toMatch(/canary/);
    expect(result?.content).not.toContain("OPENCLAW_CANARY_abcdef0123456789");
    expect(result?.content).toContain("[REDACTED]");
  });

  it("cancels and redacts when the outbound body carries a registered secret literal", async () => {
    recordResolvedSecret("sk-fake-test-literal-XYZ-9999");
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    const onSending = handlers.get("message_sending") as PluginHookHandlerMap["message_sending"];

    const event: PluginHookMessageSendingEvent = {
      to: "channel:test",
      content: "Per request: token=sk-fake-test-literal-XYZ-9999 done.",
    };
    const ctx: PluginHookMessageContext = { channelId: "test" };
    const result = await onSending(event, ctx);
    expect(result?.cancel).toBe(true);
    expect(result?.cancelReason).toMatch(/secret/);
    expect(result?.content).not.toContain("sk-fake-test-literal-XYZ-9999");
  });

  it("cancels when the outbound body quotes a registered external-content body", async () => {
    const externalBody = "INTERNAL_NOTES_FROM_FETCHED_URL_DO_NOT_EXFILTRATE";
    recordExternalContentBody(externalBody);
    const { api, handlers } = createRecordingApi();
    registerSecuritySandwichPlugin(api);
    const onSending = handlers.get("message_sending") as PluginHookHandlerMap["message_sending"];

    const event: PluginHookMessageSendingEvent = {
      to: "channel:test",
      content: `Quoting: ${externalBody}`,
    };
    const ctx: PluginHookMessageContext = { channelId: "test" };
    const result = await onSending(event, ctx);
    expect(result?.cancel).toBe(true);
    expect(result?.content).toContain("[REDACTED]");
  });
});

describe(`${SECURITY_SANDWICH_PLUGIN_ID}: injection corpus`, () => {
  beforeEach(() => {
    clearResolvedSecretsForTests();
    clearExternalContentBodiesForTests();
  });
  afterEach(() => {
    clearResolvedSecretsForTests();
    clearExternalContentBodiesForTests();
  });

  it("blocks every adversarial entry and lets every benign entry through", () => {
    const corpus = loadCorpus();
    expect(corpus.length).toBeGreaterThanOrEqual(8);

    let adversarial = 0;
    let blockedAdversarial = 0;
    let benign = 0;
    let allowedBenign = 0;
    const misclassified: string[] = [];

    for (const entry of corpus) {
      // The redaction registries are process-global, so seed only when the
      // entry needs it and clear between cases via beforeEach.
      if (entry.seedSecretLiteral) {
        recordResolvedSecret(entry.seedSecretLiteral);
      }
      const scan = scanOutboundContent(entry.outboundContent);
      if (entry.expectsBlocked) {
        adversarial += 1;
        if (!scan.safe) {
          blockedAdversarial += 1;
        } else {
          misclassified.push(`leaked: ${entry.id}`);
        }
      } else {
        benign += 1;
        if (scan.safe) {
          allowedBenign += 1;
        } else {
          misclassified.push(`false-positive: ${entry.id}`);
        }
      }
      if (entry.seedSecretLiteral) {
        clearResolvedSecretsForTests();
      }
    }

    // Both directions must be perfect on the deterministic corpus. The "≥80%
    // reduction" acceptance from the blueprint is end-to-end and lives as a
    // follow-up; here we hold the plugin to 100% on hand-crafted payloads.
    expect(misclassified, misclassified.join("; ")).toEqual([]);
    expect(blockedAdversarial).toBe(adversarial);
    expect(allowedBenign).toBe(benign);
  });
});
