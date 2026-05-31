/**
 * Owner: plugins/capabilities.
 *
 * G.1 — plugin capability manifest. Adds a declared-capability surface to
 * the plugin trust model so plugin behaviour is bounded by a manifest
 * the install gate verified against the signature, instead of plugins
 * holding ambient Gateway-process privileges.
 *
 * Threat model: upstream's SECURITY.md treats plugins as fully trusted
 * code (same OS privileges as the Gateway process). This fork's policy
 * (see SECURITY.md fork override) treats prompt injection as in-scope,
 * which means an attacker who can talk the operator into installing one
 * malicious plugin should still face least-privilege boundaries from
 * other plugins. Capability manifests are the documented declaration:
 * plugins state what they need, the install gate (P1.7 signing) covers
 * the manifest in the signed manifest hash, and runtime enforcement
 * refuses calls outside the declared surface.
 *
 * @stable
 */

export type PluginHookName =
  | "before_prompt_build"
  | "before_tool_call"
  | "message_sending"
  | "post_tool_result"
  | "post_message_send"
  | "session_start"
  | "session_end";

export type PluginFsScope =
  | "workspace.read"
  | "workspace.write"
  | "skills.read"
  | "memory.read"
  | "memory.write";

/**
 * Declared capability set for a plugin. Every field is an opt-in
 * allowlist: empty/undefined means "no calls in this category". The
 * install-time gate (task #23 follow-up) verifies the manifest against
 * the signed plugin hash; the runtime enforcement gate (also task #23)
 * refuses every plugin call that exceeds these bounds.
 *
 * The microvm sandbox seccomp profile (task #24, depends on F.1) derives
 * its kernel-level allowlist from the same manifest.
 */
export type PluginCapabilities = {
  /** Hook names the plugin will register. Names not listed cannot fire. */
  hooks?: ReadonlyArray<PluginHookName>;
  /** Provider plugin ids declared. Empty = plugin registers no providers. */
  providers?: ReadonlyArray<string>;
  /** Tool ids the plugin contributes to the agent's tool surface. */
  tools?: ReadonlyArray<string>;
  /** Channel ids the plugin owns. */
  channels?: ReadonlyArray<string>;
  /** Allowlisted outbound HTTP hosts. */
  httpAllowlist?: ReadonlyArray<string>;
  /** Filesystem scopes the plugin requires (read/write of named domains). */
  fsScopes?: ReadonlyArray<PluginFsScope>;
};

/**
 * Result of checking a runtime call against a plugin's declared capability
 * manifest. Discriminated union — callers branch on `ok`.
 */
export type CapabilityCheckResult =
  | { ok: true }
  | { ok: false; reason: string; category: keyof PluginCapabilities };

/**
 * Assert that a hook firing is declared by the plugin manifest. Used at
 * runtime when the host hook runner dispatches a hook event to a plugin.
 *
 * Failure: returns `{ok: false, ...}` rather than throwing because the
 * host hook runner needs to log + emit a structured event before bailing.
 */
export function checkHookCapability(
  capabilities: PluginCapabilities | undefined,
  hookName: PluginHookName,
): CapabilityCheckResult {
  const declared = capabilities?.hooks;
  if (!declared || declared.length === 0) {
    return { ok: false, reason: `hook "${hookName}" not declared`, category: "hooks" };
  }
  if (!declared.includes(hookName)) {
    return {
      ok: false,
      reason: `hook "${hookName}" not in declared set: ${declared.join(", ")}`,
      category: "hooks",
    };
  }
  return { ok: true };
}

/**
 * Assert that an outbound HTTP host is declared by the plugin manifest's
 * httpAllowlist. Host-only match (no scheme, no path) — the gateway's
 * fetch wrapper supplies the parsed Host header.
 *
 * Failure modes the runtime fetch wrapper must surface:
 *  - manifest declared no httpAllowlist → all hosts refused
 *  - host not in declared list → that host refused
 */
export function checkHttpAllowlist(
  capabilities: PluginCapabilities | undefined,
  host: string,
): CapabilityCheckResult {
  if (typeof host !== "string" || host.length === 0) {
    return { ok: false, reason: "empty host", category: "httpAllowlist" };
  }
  const declared = capabilities?.httpAllowlist;
  if (!declared || declared.length === 0) {
    return { ok: false, reason: "manifest declared no httpAllowlist", category: "httpAllowlist" };
  }
  if (!declared.includes(host)) {
    return {
      ok: false,
      reason: `host "${host}" not in declared httpAllowlist`,
      category: "httpAllowlist",
    };
  }
  return { ok: true };
}

/**
 * Assert that a filesystem scope is declared by the plugin manifest.
 */
export function checkFsScope(
  capabilities: PluginCapabilities | undefined,
  scope: PluginFsScope,
): CapabilityCheckResult {
  const declared = capabilities?.fsScopes;
  if (!declared || declared.length === 0) {
    return { ok: false, reason: `fs scope "${scope}" not declared`, category: "fsScopes" };
  }
  if (!declared.includes(scope)) {
    return {
      ok: false,
      reason: `fs scope "${scope}" not in declared set: ${declared.join(", ")}`,
      category: "fsScopes",
    };
  }
  return { ok: true };
}

/**
 * Normalize an unknown raw object (e.g. parsed from `openclaw.plugin.json`)
 * to a strongly-typed `PluginCapabilities`. Returns `null` for any
 * non-object input; otherwise treats every category as opt-in and
 * filters string entries.
 */
export function normalizeCapabilitiesManifest(raw: unknown): PluginCapabilities | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const obj = raw as Record<string, unknown>;
  const out: PluginCapabilities = {};
  const hooks = pickStringArray(obj.hooks);
  if (hooks) {
    out.hooks = hooks.filter(isPluginHookName);
  }
  const providers = pickStringArray(obj.providers);
  if (providers) {
    out.providers = providers;
  }
  const tools = pickStringArray(obj.tools);
  if (tools) {
    out.tools = tools;
  }
  const channels = pickStringArray(obj.channels);
  if (channels) {
    out.channels = channels;
  }
  const httpAllowlist = pickStringArray(obj.httpAllowlist);
  if (httpAllowlist) {
    out.httpAllowlist = httpAllowlist;
  }
  const fsScopes = pickStringArray(obj.fsScopes);
  if (fsScopes) {
    out.fsScopes = fsScopes.filter(isPluginFsScope);
  }
  return out;
}

// C.2 — runtime accessor. Populated by the install-signing gate after the
// signed manifest's capabilities block parses cleanly; consulted by the
// hook-runtime warn-mode gate (C.3) and downstream HTTP/FS guards (E
// workstream) to bound plugin behavior to its declared surface.
const pluginCapabilitiesById = new Map<string, PluginCapabilities>();

/**
 * Cache a plugin's declared capability surface keyed by id. Called once
 * per plugin install / load by the install-signing gate; subsequent
 * runtime calls read via `getPluginCapabilities`. Idempotent — re-calls
 * with the same id overwrite (matches plugin upgrade behavior).
 *
 * @stable
 */
export function setPluginCapabilities(pluginId: string, capabilities: PluginCapabilities): void {
  if (typeof pluginId !== "string" || pluginId.length === 0) {
    return;
  }
  pluginCapabilitiesById.set(pluginId, capabilities);
}

/**
 * Look up a plugin's declared capability surface by id. Returns
 * `undefined` when the plugin has never declared a capability manifest —
 * the runtime gate then falls back to whatever its "no declared surface"
 * policy is (warn-mode logs + counts; strict-mode refuses).
 *
 * @stable
 */
export function getPluginCapabilities(pluginId: string): PluginCapabilities | undefined {
  if (typeof pluginId !== "string" || pluginId.length === 0) {
    return undefined;
  }
  return pluginCapabilitiesById.get(pluginId);
}

/**
 * Test-only: wipe the per-process capability cache between tests so a
 * registration in one test cannot leak into the next.
 *
 * @internal
 */
export function clearPluginCapabilitiesForTests(): void {
  pluginCapabilitiesById.clear();
}

const HOOK_NAMES: ReadonlySet<PluginHookName> = new Set([
  "before_prompt_build",
  "before_tool_call",
  "message_sending",
  "post_tool_result",
  "post_message_send",
  "session_start",
  "session_end",
]);

const FS_SCOPES: ReadonlySet<PluginFsScope> = new Set([
  "workspace.read",
  "workspace.write",
  "skills.read",
  "memory.read",
  "memory.write",
]);

function isPluginHookName(value: string): value is PluginHookName {
  return HOOK_NAMES.has(value as PluginHookName);
}

function isPluginFsScope(value: string): value is PluginFsScope {
  return FS_SCOPES.has(value as PluginFsScope);
}

function pickStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  return value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0);
}
