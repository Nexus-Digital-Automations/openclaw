// Owner: plugins/install-approval.test
//
// Spec: the install-approval decision table (Track A). The gate is a pure
// decision function — these drive it directly, independent of the rollout flag.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  applyInstallApprovalGate,
  type InstallApprovalGateParams,
  isInstallApprovalEnabled,
  PLUGIN_INSTALL_APPROVAL_CODE,
} from "./install-approval.js";
import type { PluginApprovalResolver } from "./install-approval.types.js";

const HASH = "a".repeat(64);
const OTHER_HASH = "b".repeat(64);
const FINGERPRINT = "f".repeat(32);
const FIXED_NOW = () => new Date("2026-01-01T00:00:00.000Z");

function baseParams(overrides: Partial<InstallApprovalGateParams>): InstallApprovalGateParams {
  return {
    sourceDir: "/tmp/openclaw-approval-fixture",
    pluginId: "demo",
    pluginHash: HASH,
    publisherFingerprint: FINGERPRINT,
    logger: { info: vi.fn(), warn: vi.fn() },
    now: FIXED_NOW,
    // Default: no prior approval (so we never touch the real index).
    loadPriorApprovedHash: async () => undefined,
    ...overrides,
  };
}

describe("applyInstallApprovalGate decision table", () => {
  it("auto-approves a trusted-source install without prompting or pinning", async () => {
    const resolver = vi.fn();
    const result = await applyInstallApprovalGate(
      baseParams({ trustedSourceLinkedOfficialInstall: true, approvalResolver: resolver }),
    );
    expect(result).toEqual({ ok: true });
    expect(resolver).not.toHaveBeenCalled();
  });

  it("approves and pins when assumeApproved is set, without prompting", async () => {
    const resolver = vi.fn();
    const result = await applyInstallApprovalGate(
      baseParams({ assumeApproved: true, approvalResolver: resolver }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.approval?.approvedHash).toBe(HASH);
      expect(result.approval?.approvedPublisherFingerprint).toBe(FINGERPRINT);
      expect(result.approval?.approvedAt).toBe("2026-01-01T00:00:00.000Z");
    }
    expect(resolver).not.toHaveBeenCalled();
  });

  it("skips the prompt when the prior approved hash matches (pinned-match)", async () => {
    const resolver = vi.fn();
    const result = await applyInstallApprovalGate(
      baseParams({ loadPriorApprovedHash: async () => HASH, approvalResolver: resolver }),
    );
    expect(result.ok).toBe(true);
    expect(resolver).not.toHaveBeenCalled();
  });

  it("re-prompts on a changed hash and flags isUpgrade + previousApprovedHash", async () => {
    const resolver = vi.fn<PluginApprovalResolver>(async () => ({ kind: "approved" }));
    const result = await applyInstallApprovalGate(
      baseParams({ loadPriorApprovedHash: async () => OTHER_HASH, approvalResolver: resolver }),
    );
    expect(result.ok).toBe(true);
    expect(resolver).toHaveBeenCalledTimes(1);
    const context = resolver.mock.calls[0]?.[0];
    expect(context?.isUpgrade).toBe(true);
    expect(context?.previousApprovedHash).toBe(OTHER_HASH);
    expect(context?.trust).toBe("trusted-publisher");
  });

  it("refuses with approval_denied when the resolver denies", async () => {
    const resolver = vi.fn(async () => ({ kind: "denied" as const, reason: "user said no" }));
    const result = await applyInstallApprovalGate(baseParams({ approvalResolver: resolver }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PLUGIN_INSTALL_APPROVAL_CODE.APPROVAL_DENIED);
    }
  });

  it("fails closed with approval_required when no resolver and not assumeApproved", async () => {
    const result = await applyInstallApprovalGate(baseParams({}));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PLUGIN_INSTALL_APPROVAL_CODE.APPROVAL_REQUIRED);
    }
  });

  it("marks an unsigned install (no publisher) as unsigned-allowed trust", async () => {
    const resolver = vi.fn<PluginApprovalResolver>(async () => ({ kind: "approved" }));
    const result = await applyInstallApprovalGate(
      baseParams({ publisherFingerprint: undefined, approvalResolver: resolver }),
    );
    expect(result.ok).toBe(true);
    expect(resolver.mock.calls[0]?.[0]?.trust).toBe("unsigned-allowed");
    if (result.ok) {
      expect(result.approval?.approvedPublisherFingerprint).toBeUndefined();
    }
  });
});

describe("isInstallApprovalEnabled", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("defaults off when the rollout env var is unset", () => {
    vi.stubEnv("OPENCLAW_REQUIRE_PLUGIN_APPROVAL", "");
    expect(isInstallApprovalEnabled()).toBe(false);
  });

  it("is on when the rollout env var is truthy", () => {
    vi.stubEnv("OPENCLAW_REQUIRE_PLUGIN_APPROVAL", "1");
    expect(isInstallApprovalEnabled()).toBe(true);
  });
});
