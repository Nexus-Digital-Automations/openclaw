// Owner: plugins/install-approval. The install-time user-approval gate (Track A).
// Runs inside the shared signing gate (so both the package and bundle funnels
// share it with no bypass) AFTER signature/publisher checks pass. Decides
// whether a third-party plugin install may proceed:
//
//   1. trusted-source / bundled origin  -> auto-approve (first-party, never gated)
//   2. assumeApproved (--yes / explicit) -> approve + pin
//   3. prior approved hash === this hash -> already approved this version, skip
//   4. resolver present                  -> ask the human; honor allow/deny
//   5. otherwise                         -> FAIL CLOSED (non-interactive default-deny)
//
// The funnel injects the resolver; this module never touches a TTY.

import type { PluginCapabilities } from "./capabilities.js";
import type {
  ApprovedInstallFacts,
  PluginApprovalResolver,
  PluginApprovalTrust,
} from "./install-approval.types.js";
import { loadInstalledPluginIndexInstallRecords } from "./installed-plugin-index-records.js";
import { canonicalPluginHashHex } from "./plugins-lock.runtime.js";

export const PLUGIN_INSTALL_APPROVAL_CODE = {
  APPROVAL_REQUIRED: "plugin.install.approval_required",
  APPROVAL_DENIED: "plugin.install.approval_denied",
} as const;

export type PluginInstallApprovalCode =
  (typeof PLUGIN_INSTALL_APPROVAL_CODE)[keyof typeof PLUGIN_INSTALL_APPROVAL_CODE];

/**
 * Rollout switch (default OFF), mirroring OPENCLAW_REQUIRE_SIGNED_PLUGINS. While
 * off, the funnel does not invoke the approval gate at all — installs behave
 * exactly as before. Flipping it on (after callers/tests are migrated) makes
 * external installs require approval. The gate's decision logic below is always
 * exercisable directly (tests call it without this flag).
 */
export function isInstallApprovalEnabled(): boolean {
  const raw = process.env.OPENCLAW_REQUIRE_PLUGIN_APPROVAL?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

type ApprovalLogger = {
  info?: (message: string) => void;
  warn?: (message: string) => void;
};

export type InstallApprovalGateParams = {
  sourceDir: string;
  pluginId: string;
  // Reused from the signing gate's computed hash on the signed path; on the
  // unsigned-allowed path it is absent and computed here once.
  pluginHash?: string;
  publisherFingerprint?: string;
  capabilities?: PluginCapabilities;
  // Exemption — first-party / official installs are never gated. This is the
  // ONLY exemption: "installed via the bundle funnel" does NOT exempt, because a
  // user-supplied bundle is still external/untrusted.
  trustedSourceLinkedOfficialInstall?: boolean;
  // `--yes` / explicit programmatic opt-in.
  assumeApproved?: boolean;
  approvalResolver?: PluginApprovalResolver;
  logger?: ApprovalLogger;
  now?: () => Date;
  // Test seam: override the prior-approval lookup.
  loadPriorApprovedHash?: (pluginId: string) => Promise<string | undefined>;
};

export type InstallApprovalGateResult =
  | { ok: true; approval?: ApprovedInstallFacts }
  | { ok: false; code: PluginInstallApprovalCode; reason: string };

function emitApprovalEvent(
  logger: ApprovalLogger | undefined,
  level: "info" | "warn",
  fields: Record<string, unknown>,
): void {
  const line = JSON.stringify(fields);
  if (level === "warn") {
    logger?.warn?.(line);
    return;
  }
  logger?.info?.(line);
}

// Missing/corrupt index => treat as "no prior approval" so we fail toward
// prompting, never toward silent auto-approve.
async function defaultLoadPriorApprovedHash(pluginId: string): Promise<string | undefined> {
  try {
    const records = await loadInstalledPluginIndexInstallRecords();
    return records[pluginId]?.approvedHash;
  } catch {
    return undefined;
  }
}

/**
 * Gate an install on user approval. Returns ok:true (with optional approval
 * facts to pin) when the install may proceed, or ok:false with a refusal code
 * when it must abort. Never throws on expected refusal paths and never performs
 * interactive I/O — the host's injected resolver owns the human interaction.
 *
 * @stable
 */
export async function applyInstallApprovalGate(
  params: InstallApprovalGateParams,
): Promise<InstallApprovalGateResult> {
  const { pluginId, logger } = params;

  if (params.trustedSourceLinkedOfficialInstall) {
    emitApprovalEvent(logger, "info", {
      event: "plugin.install.approval.auto_approved_trusted",
      pluginId,
      origin: "trusted-source",
    });
    return { ok: true };
  }

  const approvedHash = params.pluginHash ?? (await canonicalPluginHashHex(params.sourceDir));
  const trust: PluginApprovalTrust = params.publisherFingerprint
    ? "trusted-publisher"
    : "unsigned-allowed";
  const facts: ApprovedInstallFacts = {
    approvedHash,
    approvedAt: (params.now?.() ?? new Date()).toISOString(),
    ...(params.publisherFingerprint
      ? { approvedPublisherFingerprint: params.publisherFingerprint }
      : {}),
  };

  if (params.assumeApproved) {
    emitApprovalEvent(logger, "info", {
      event: "plugin.install.approval.approved",
      pluginId,
      approvedHash,
      reason: "assume-approved",
    });
    return { ok: true, approval: facts };
  }

  const loadPrior = params.loadPriorApprovedHash ?? defaultLoadPriorApprovedHash;
  const previousApprovedHash = await loadPrior(pluginId);

  if (previousApprovedHash && previousApprovedHash === approvedHash) {
    emitApprovalEvent(logger, "info", {
      event: "plugin.install.approval.approved",
      pluginId,
      approvedHash,
      reason: "pinned-match",
    });
    return { ok: true, approval: facts };
  }

  const isUpgrade = Boolean(previousApprovedHash && previousApprovedHash !== approvedHash);

  if (!params.approvalResolver) {
    emitApprovalEvent(logger, "warn", {
      event: "plugin.install.approval.required",
      pluginId,
      approvedHash,
      isUpgrade,
    });
    return {
      ok: false,
      code: PLUGIN_INSTALL_APPROVAL_CODE.APPROVAL_REQUIRED,
      reason: `plugin "${pluginId}" requires approval to install; rerun interactively or pass --yes`,
    };
  }

  const decision = await params.approvalResolver({
    pluginId,
    approvedHash,
    trust,
    isUpgrade,
    ...(params.publisherFingerprint ? { publisherFingerprint: params.publisherFingerprint } : {}),
    ...(params.capabilities ? { capabilities: params.capabilities } : {}),
    ...(previousApprovedHash ? { previousApprovedHash } : {}),
  });

  if (decision.kind === "denied") {
    emitApprovalEvent(logger, "warn", {
      event: "plugin.install.approval.denied",
      pluginId,
      approvedHash,
      ...(decision.reason ? { reason: decision.reason } : {}),
    });
    return {
      ok: false,
      code: PLUGIN_INSTALL_APPROVAL_CODE.APPROVAL_DENIED,
      reason: decision.reason ?? `install of plugin "${pluginId}" was not approved`,
    };
  }

  emitApprovalEvent(logger, "info", {
    event: "plugin.install.approval.approved",
    pluginId,
    approvedHash,
    reason: "interactive",
  });
  return { ok: true, approval: facts };
}
