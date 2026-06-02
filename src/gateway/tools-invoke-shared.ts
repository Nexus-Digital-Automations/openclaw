import {
  normalizeOptionalLowercaseString,
  normalizeOptionalString,
} from "@openclaw/normalization-core/string-coerce";
import { runBeforeToolCallHook } from "../agents/agent-tools.before-tool-call.js";
import { resolveToolLoopDetectionConfig } from "../agents/agent-tools.js";
import { getChannelAgentToolMeta } from "../agents/channel-tools.js";
import { isKnownCoreToolId } from "../agents/tool-catalog.js";
import { ToolInputError, type AnyAgentTool } from "../agents/tools/common.js";
import { resolveMainSessionKey } from "../config/sessions.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { logWarn } from "../logger.js";
import { isTestDefaultMemorySlotDisabled } from "../plugins/config-state.js";
import { defaultSlotIdForKey } from "../plugins/slots.js";
import { getPluginToolMeta } from "../plugins/tools.js";
import { tryAppendAuditEntry } from "../security/audit-chain.js";
import { createToolOutputRedactor } from "../security/tool-output-redactor.js";
import {
  computeTurnSalt,
  currentSessionTurnCounter,
  parseToolNameSalt,
} from "../security/tool-name-salt.js";
import {
  envelopeHash,
  verifyEnvelope,
  type VerifiedCmdEnvelope,
} from "../security/verified-cmd.js";
import { canonicalizeSessionKeyForAgent } from "./session-store-key.js";
import { resolveGatewayScopedTools } from "./tool-resolution.js";

const MEMORY_TOOL_NAMES = new Set(["memory_search", "memory_get"]);

export type ToolsInvokeInput = {
  tool?: unknown;
  name?: unknown;
  action?: unknown;
  args?: unknown;
  sessionKey?: unknown;
  agentId?: unknown;
  idempotencyKey?: unknown;
  dryRun?: unknown;
  // P1.1 verified-cmd envelope minted at extract time by the transport-stream.
  // When `verifiedCmd.expectedPrevHash` is set on the dispatch call, the
  // envelope is required and must chain-verify.
  verifiedCmd?: VerifiedCmdEnvelope;
};

type ToolsInvokeErrorType =
  | "invalid_request"
  | "not_found"
  | "tool_call_blocked"
  | "tool_error"
  | "verified_cmd_failure";

type ToolsInvokeOutcome =
  | {
      ok: true;
      status: 200;
      toolName: string;
      source: "core" | "plugin" | "channel";
      result: unknown;
      // P1.1: hash of the dispatched envelope. Callers chain the next call's
      // prevHash to this value. Only set when verified-cmd was enforced.
      verifiedCmdHash?: string;
    }
  | {
      ok: false;
      status: 400 | 403 | 404 | 500;
      toolName: string;
      error: {
        type: ToolsInvokeErrorType;
        message: string;
        // P1.1 fine-grained error code (e.g. "verified_cmd.missing_nonce",
        // "verified_cmd.chain_break"). Present only for verified-cmd refusals.
        code?: string;
        requiresApproval?: boolean;
      };
    };

function resolveSessionKey(params: { cfg: OpenClawConfig; input: ToolsInvokeInput }): string {
  const rawSessionKey = normalizeOptionalString(params.input.sessionKey);
  if (rawSessionKey && rawSessionKey !== "main") {
    return rawSessionKey;
  }
  const agentId = normalizeOptionalString(params.input.agentId);
  if (agentId) {
    return canonicalizeSessionKeyForAgent(agentId, "main");
  }
  return resolveMainSessionKey(params.cfg);
}

function resolveMemoryToolDisableReasons(cfg: OpenClawConfig): string[] {
  if (!process.env.VITEST) {
    return [];
  }
  const reasons: string[] = [];
  const plugins = cfg.plugins;
  const slotRaw = plugins?.slots?.memory;
  const slotDisabled = slotRaw === null || normalizeOptionalLowercaseString(slotRaw) === "none";
  const pluginsDisabled = plugins?.enabled === false;
  const defaultDisabled = isTestDefaultMemorySlotDisabled(cfg);

  if (pluginsDisabled) {
    reasons.push("plugins.enabled=false");
  }
  if (slotDisabled) {
    reasons.push(slotRaw === null ? "plugins.slots.memory=null" : 'plugins.slots.memory="none"');
  }
  if (!pluginsDisabled && !slotDisabled && defaultDisabled) {
    reasons.push("memory plugin disabled by test default");
  }
  return reasons;
}

function mergeActionIntoArgsIfSupported(params: {
  toolSchema: unknown;
  action: string | undefined;
  args: Record<string, unknown>;
}): Record<string, unknown> {
  const { toolSchema, action, args } = params;
  if (!action || args.action !== undefined) {
    return args;
  }
  const schemaObj = toolSchema as { properties?: Record<string, unknown> } | null;
  const hasAction = Boolean(
    schemaObj &&
    typeof schemaObj === "object" &&
    schemaObj.properties &&
    "action" in schemaObj.properties,
  );
  return hasAction ? { ...args, action } : args;
}

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message || String(err);
  }
  if (typeof err === "string") {
    return err;
  }
  return String(err);
}

function resolveToolInputErrorStatus(err: unknown): number | null {
  if (err instanceof ToolInputError) {
    const status = (err as { status?: unknown }).status;
    return typeof status === "number" ? status : 400;
  }
  if (typeof err !== "object" || err === null || !("name" in err)) {
    return null;
  }
  const name = (err as { name?: unknown }).name;
  if (name !== "ToolInputError" && name !== "ToolAuthorizationError") {
    return null;
  }
  const status = (err as { status?: unknown }).status;
  if (typeof status === "number") {
    return status;
  }
  return name === "ToolAuthorizationError" ? 403 : 400;
}

// Redactor must never block a tool result from reaching the model: a crash in
// the AC scanner degrades to passthrough + logged event, symmetric to the
// best-effort audit-write posture in `tryAppendAuditEntry`.
function redactToolOutputSafely(result: unknown): unknown {
  try {
    const redactor = createToolOutputRedactor();
    return redactor.redact(result);
  } catch (err) {
    logWarn(`tool_output_redactor.error: ${String(err)}`);
    return result;
  }
}

function resolveToolSource(tool: AnyAgentTool): "core" | "plugin" | "channel" {
  if (getPluginToolMeta(tool)) {
    return "plugin";
  }
  if (getChannelAgentToolMeta(tool as never)) {
    return "channel";
  }
  return "core";
}

const TOOL_NAME_SALT_DELIMITER = "__cz_";

/**
 * Reverse the schema-fuzz salt suffix on an on-the-wire tool name.
 *
 * - Name without the delimiter passes through unchanged (legacy callers,
 *   current production state where the forward map is not yet activated).
 * - Name with the delimiter and a matching session salt returns the
 *   original tool name.
 * - Name with the delimiter but mismatched salt returns `null` so the
 *   caller surfaces a structured refusal. Silently looking up the
 *   unsalted name would defeat the defense.
 */
function resolveSaltedToolName(rawToolName: string, sessionKeyInput: unknown): string | null {
  if (!rawToolName.includes(TOOL_NAME_SALT_DELIMITER)) {
    return rawToolName;
  }
  const sessionKey = normalizeOptionalString(sessionKeyInput);
  if (!sessionKey) {
    return null;
  }
  const turnCounter = currentSessionTurnCounter(sessionKey);
  if (turnCounter <= 0) {
    return null;
  }
  const expectedSalt = computeTurnSalt(sessionKey, turnCounter);
  return parseToolNameSalt(rawToolName, expectedSalt);
}

export async function invokeGatewayTool(params: {
  cfg: OpenClawConfig;
  input: ToolsInvokeInput;
  messageChannel?: string;
  accountId?: string;
  agentTo?: string;
  agentThreadId?: string;
  senderIsOwner?: boolean;
  toolCallIdPrefix: string;
  approvalMode?: "request" | "report";
  // P1.1: when set, the caller is in verified-cmd mode. Envelope MUST be
  // present on `input.verifiedCmd` and chain to this previous-hash; absence
  // or break refuses the call. Backward-compatible: unset = legacy path.
  expectedPrevHash?: string;
}): Promise<ToolsInvokeOutcome> {
  const rawToolName = normalizeOptionalString(params.input.name ?? params.input.tool) ?? "";
  if (!rawToolName) {
    return {
      ok: false,
      status: 400,
      toolName: "",
      error: { type: "invalid_request", message: "tools.invoke requires name" },
    };
  }
  // A.2 — reverse-map schema-fuzz salt. If the on-the-wire tool name carries
  // the salt delimiter, attempt to parse against the current session's salt.
  // Mismatch (delimiter present, salt wrong) is an injection-shaped refusal,
  // NOT a silent fallback. Names without the delimiter pass through verbatim
  // so unsalted callers (current production state) keep working.
  const toolName = resolveSaltedToolName(rawToolName, params.input.sessionKey);
  if (toolName === null) {
    logWarn(
      `[tool-name-salt] refusing tool dispatch: salted-name mismatch tool=${rawToolName}`,
    );
    return {
      ok: false,
      status: 400,
      toolName: rawToolName,
      error: {
        type: "invalid_request",
        message: "Tool name carries schema-fuzz salt that does not match this session's turn salt.",
        code: "tool_name_salt.mismatch",
      },
    };
  }

  let verifiedCmdHash: string | undefined;
  if (params.expectedPrevHash !== undefined) {
    const verdict = verifyEnvelope(params.input.verifiedCmd, params.expectedPrevHash);
    if (!verdict.ok) {
      const code =
        verdict.reason === "envelope_missing"
          ? "verified_cmd.missing_nonce"
          : verdict.reason === "chain_break"
            ? "verified_cmd.chain_break"
            : "verified_cmd.shape_invalid";
      logWarn(
        `[verified-cmd] refusing tool dispatch: ${verdict.reason}` +
          ` tool=${toolName} code=${code}`,
      );
      return {
        ok: false,
        status: 403,
        toolName,
        error: {
          type: "verified_cmd_failure",
          message: `verified-cmd refused: ${verdict.reason}`,
          code,
        },
      };
    }
    verifiedCmdHash = envelopeHash(params.input.verifiedCmd as VerifiedCmdEnvelope);
  }

  if (process.env.VITEST && MEMORY_TOOL_NAMES.has(toolName)) {
    const reasons = resolveMemoryToolDisableReasons(params.cfg);
    if (reasons.length > 0) {
      const suffix = ` (${reasons.join(", ")})`;
      return {
        ok: false,
        status: 400,
        toolName,
        error: {
          type: "invalid_request",
          message:
            `memory tools are disabled in tests${suffix}. ` +
            `Enable by setting plugins.slots.memory="${defaultSlotIdForKey("memory")}" (and ensure plugins.enabled is not false).`,
        },
      };
    }
  }

  const knownCoreTool = isKnownCoreToolId(toolName);
  const gatewayRequestedTools = knownCoreTool ? [] : [toolName];

  const action = normalizeOptionalString(params.input.action);
  const argsRaw = params.input.args;
  const args =
    argsRaw && typeof argsRaw === "object" && !Array.isArray(argsRaw)
      ? (argsRaw as Record<string, unknown>)
      : {};
  const sessionKey = resolveSessionKey({ cfg: params.cfg, input: params.input });
  const resolveTools = (disablePluginTools: boolean) =>
    resolveGatewayScopedTools({
      cfg: params.cfg,
      sessionKey,
      messageProvider: params.messageChannel,
      accountId: params.accountId,
      agentTo: params.agentTo,
      agentThreadId: params.agentThreadId,
      senderIsOwner: params.senderIsOwner,
      allowGatewaySubagentBinding: true,
      allowMediaInvokeCommands: true,
      surface: "http",
      disablePluginTools,
      gatewayRequestedTools,
    });

  let { agentId, tools } = resolveTools(knownCoreTool);
  if (knownCoreTool && !tools.some((candidate) => candidate.name === toolName)) {
    ({ agentId, tools } = resolveTools(false));
  }
  const requestedAgentId = normalizeOptionalString(params.input.agentId);
  if (requestedAgentId && agentId && requestedAgentId !== agentId) {
    return {
      ok: false,
      status: 400,
      toolName,
      error: {
        type: "invalid_request",
        message: `agent id "${requestedAgentId}" does not match session agent "${agentId}"`,
      },
    };
  }
  const tool = tools.find((candidate) => candidate.name === toolName);
  if (!tool) {
    return {
      ok: false,
      status: 404,
      toolName,
      error: { type: "not_found", message: `Tool not available: ${toolName}` },
    };
  }

  try {
    const gatewayTool: AnyAgentTool = tool;
    const idempotencyKey = normalizeOptionalString(params.input.idempotencyKey);
    const toolCallId = idempotencyKey
      ? `${params.toolCallIdPrefix}-${idempotencyKey}`
      : `${params.toolCallIdPrefix}-${Date.now()}`;
    const toolArgs = mergeActionIntoArgsIfSupported({
      toolSchema: gatewayTool.parameters,
      action,
      args,
    });
    const hookResult = await runBeforeToolCallHook({
      toolName,
      params: toolArgs,
      toolCallId,
      ctx: {
        agentId,
        config: params.cfg,
        sessionKey,
        loopDetection: resolveToolLoopDetectionConfig({ cfg: params.cfg, agentId }),
      },
      approvalMode: params.approvalMode,
    });
    if (hookResult.blocked) {
      return {
        ok: false,
        status: 403,
        toolName,
        error: {
          type: "tool_call_blocked",
          message: hookResult.reason,
          requiresApproval: hookResult.deniedReason === "plugin-approval",
        },
      };
    }
    const executionResult = await gatewayTool.execute?.(toolCallId, hookResult.params);
    tryAppendAuditEntry({
      entryId: toolCallId,
      toolName,
      argv: hookResult.params,
    });
    return {
      ok: true,
      status: 200,
      toolName,
      source: resolveToolSource(gatewayTool),
      result: redactToolOutputSafely(executionResult),
      verifiedCmdHash,
    };
  } catch (err) {
    const inputStatus = resolveToolInputErrorStatus(err);
    if (inputStatus !== null) {
      return {
        ok: false,
        status: inputStatus === 403 ? 403 : 400,
        toolName,
        error: {
          type: "tool_error",
          message: getErrorMessage(err) || "invalid tool arguments",
        },
      };
    }
    logWarn(`tools-invoke: tool execution failed: ${String(err)}`);
    return {
      ok: false,
      status: 500,
      toolName,
      error: { type: "tool_error", message: "tool execution failed" },
    };
  }
}
