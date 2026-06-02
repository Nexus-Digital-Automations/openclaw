// Shared tool-risk constants.
// Keep these centralized so gateway HTTP restrictions and security audits don't drift.

/**
 * Tools denied via Gateway HTTP `POST /tools/invoke` by default.
 * These are high-risk because they enable session orchestration, control-plane actions,
 * or interactive flows that don't make sense over a non-interactive HTTP surface.
 */
export const DEFAULT_GATEWAY_HTTP_TOOL_DENY = [
  // Direct command execution — immediate RCE surface
  "exec",
  // Arbitrary child process creation — immediate RCE surface
  "spawn",
  // Shell command execution — immediate RCE surface
  "shell",
  // Background command sessions — drives long-running host processes
  "process",
  // Fresh-content file write — arbitrary file creation/overwrite on the host.
  // Must be the canonical core tool id (`write`), not `fs_write`: the gateway
  // filter is an exact `denySet.has(tool.name)` test, so a non-id never denies.
  "write",
  // Existing-content file edit — arbitrary file mutation on the host
  "edit",
  // Patch application can rewrite arbitrary files
  "apply_patch",
  // Session orchestration — spawning agents remotely is RCE
  "sessions_spawn",
  // Cross-session injection — message injection across sessions
  "sessions_send",
  // Persistent automation control plane — can create/update/remove scheduled runs
  "cron",
  // Gateway control plane — prevents gateway reconfiguration via HTTP
  "gateway",
  // Node command relay can reach system.run on paired hosts
  "nodes",
] as const;
