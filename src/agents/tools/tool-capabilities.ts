/**
 * Owner: agents/tools security gate.
 *
 * Maps tools to the security capabilities they exercise so the external-content
 * taint gate (`agent-tools.before-tool-call.ts`) can decide, per capability,
 * whether a tainted argv value must force operator approval. Replaces the old
 * hard-coded three-name allowlist (`exec`/`write`/`apply_patch`): every
 * egress/effect tool is now covered, and undeclared plugin tools fail closed.
 *
 * Resolution precedence (`resolveToolCapabilities`): an explicit `tool.capabilities`
 * declaration wins, then the static name map, then `["unknown"]` — the
 * fail-closed sentinel that treats any string parameter as dangerous.
 *
 * @internal
 */
import type { ExternalContentTaintHit } from "../../shared/process-external-content-bodies.js";
import type { ToolCapability } from "../runtime/index.js";
import { normalizeToolName } from "../tool-policy-shared.js";

export type { ToolCapability };

/**
 * Capabilities that force operator approval when a tainted value lands in one of
 * their dangerous parameters. Everything except `read-local` qualifies: a benign
 * tainted read must never gate, but any outbound, mutating, or executing surface
 * carrying attacker-influenced bytes must.
 */
const DANGEROUS_CAPABILITIES: ReadonlySet<ToolCapability> = new Set<ToolCapability>([
  "exec",
  "write",
  "edit",
  "egress",
  "message-send",
  "control-plane",
  "delayed-exec",
  "unknown",
]);

export function isDangerousCapability(capability: ToolCapability): boolean {
  return DANGEROUS_CAPABILITIES.has(capability);
}

/**
 * First-party tool name → capabilities. Names are matched after
 * `normalizeToolName` (so `bash`→`exec`, `apply-patch`→`apply_patch`). Plugin
 * tools are intentionally absent: they declare their own capabilities or fall
 * through to the fail-closed `unknown` default.
 */
const STATIC_TOOL_CAPABILITIES = new Map<string, readonly ToolCapability[]>([
  // Runtime / execution — whole argv is attacker-influenced payload.
  ["exec", ["exec"]],
  ["process", ["exec"]],
  ["code_execution", ["exec"]],
  // Files — fresh-content writers vs existing-content edit vs benign reads.
  ["write", ["write"]],
  ["apply_patch", ["write"]],
  ["edit", ["edit"]],
  ["read", ["read-local"]],
  ["ls", ["read-local"]],
  ["grep", ["read-local"]],
  ["find", ["read-local"]],
  // Web / outbound network — tainted target/body is the canonical exfil channel.
  ["web_fetch", ["egress"]],
  ["web_search", ["egress"]],
  ["x_search", ["egress"]],
  ["browser", ["egress"]],
  ["image_generate", ["egress"]],
  ["music_generate", ["egress"]],
  ["video_generate", ["egress"]],
  ["tts", ["egress"]],
  // Messaging — sends content to a human/channel.
  ["message", ["message-send"]],
  ["sessions_send", ["message-send"]],
  // Session/agent inspection — read-only, benign.
  ["sessions_list", ["read-local"]],
  ["sessions_history", ["read-local"]],
  ["agents_list", ["read-local"]],
  ["session_status", ["read-local"]],
  ["subagents", ["read-local"]],
  ["transcripts", ["read-local"]],
  ["image", ["read-local"]],
  ["update_plan", ["read-local"]],
  // Control-plane / scheduling — process control, spawns, scheduled execution.
  ["gateway", ["egress", "control-plane"]],
  ["nodes", ["control-plane"]],
  ["sessions_spawn", ["control-plane"]],
  ["canvas", ["control-plane"]],
  ["cron", ["control-plane", "delayed-exec"]],
]);

export function getStaticToolCapabilities(toolName: string): readonly ToolCapability[] | undefined {
  return STATIC_TOOL_CAPABILITIES.get(normalizeToolName(toolName));
}

/**
 * Which leaf parameter keys carry the dangerous payload for each capability.
 * `"*"` means any string leaf is the payload (exec/write put the whole argv on
 * the wire); a key set restricts gating to the parameters that actually reach
 * the dangerous sink, so a tainted-but-incidental field does not over-trigger.
 * `unknown` is `"*"` so an undeclared plugin tool gates on any tainted string.
 */
export const DANGEROUS_PARAM_KEYS: Readonly<Record<ToolCapability, ReadonlySet<string> | "*">> = {
  exec: "*",
  write: "*",
  edit: new Set(["content", "new_string", "replacement"]),
  egress: new Set(["url", "query", "body", "data"]),
  "message-send": new Set(["text", "body", "content", "label"]),
  "control-plane": new Set(["command", "schedule", "payload", "url", "path"]),
  "delayed-exec": new Set(["command", "script", "payload"]),
  "read-local": new Set(),
  unknown: "*",
};

/** Fail-closed default for any tool with neither a declaration nor a static mapping. */
const UNKNOWN_CAPABILITIES: readonly ToolCapability[] = ["unknown"];

/**
 * Resolve a tool's capabilities for the taint gate. Explicit declaration wins so
 * plugin authors can be precise; otherwise the static name map; otherwise the
 * fail-closed `["unknown"]` sentinel so an undeclared tool is treated as
 * dangerous across every parameter.
 */
export function resolveToolCapabilities(tool: {
  name: string;
  capabilities?: readonly ToolCapability[];
}): readonly ToolCapability[] {
  if (tool.capabilities && tool.capabilities.length > 0) {
    return tool.capabilities;
  }
  return getStaticToolCapabilities(tool.name) ?? UNKNOWN_CAPABILITIES;
}

/** Verdict of the capability taint gate: which dangerous capabilities a tainted argv tripped. */
export interface CapabilityTaintVerdict {
  triggered: boolean;
  triggeredCapabilities: ToolCapability[];
  matchedBodies: string[];
}

// Match a tainted leaf against a capability's dangerous keys. "*" means the whole
// argv is the payload (exec/write/unknown). Otherwise ANY path segment matching a
// dangerous key gates, so a tainted value nested under a dangerous key
// (e.g. egress "body.0.value") still trips — final-segment-only would miss it.
function paramPathIsDangerous(
  paramPath: string,
  dangerousKeys: ReadonlySet<string> | "*",
): boolean {
  if (dangerousKeys === "*") {
    return true;
  }
  if (dangerousKeys.size === 0) {
    return false;
  }
  return paramPath.split(".").some((segment) => dangerousKeys.has(segment));
}

/**
 * Decide whether tainted argv values must force operator approval. A capability
 * gates only when it is dangerous AND a tainted body landed in one of its
 * dangerous parameters — so a benign tainted read (`read.path`) passes while a
 * tainted `web_fetch.url` or `message.text` gates.
 */
export function evaluateCapabilityTaintGate(input: {
  capabilities: readonly ToolCapability[];
  hits: readonly ExternalContentTaintHit[];
}): CapabilityTaintVerdict {
  const triggeredCapabilities: ToolCapability[] = [];
  const matchedBodies = new Set<string>();
  for (const capability of input.capabilities) {
    if (!isDangerousCapability(capability)) {
      continue;
    }
    const dangerousKeys = DANGEROUS_PARAM_KEYS[capability];
    for (const hit of input.hits) {
      if (paramPathIsDangerous(hit.paramPath, dangerousKeys)) {
        if (!triggeredCapabilities.includes(capability)) {
          triggeredCapabilities.push(capability);
        }
        matchedBodies.add(hit.matchedBody);
      }
    }
  }
  return {
    triggered: triggeredCapabilities.length > 0,
    triggeredCapabilities,
    matchedBodies: [...matchedBodies],
  };
}
