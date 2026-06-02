// Owner: plugins/install-approval. Contract types for the install-time
// user-approval gate (Track A). The funnel must stay free of TTY I/O, so the
// host injects a resolver; these types are the boundary between the funnel and
// whatever surface (CLI clack prompt, wizard prompter, channel buttons) asks
// the human.

import type { PluginCapabilities } from "./capabilities.js";

// Why the install is trustworthy enough to even ask about: a verified
// first-party/known publisher, or an operator-allowed unsigned install.
export type PluginApprovalTrust = "trusted-publisher" | "unsigned-allowed";

/**
 * Everything the human needs to make an informed decision, computed at the
 * install gate. `approvedHash` is the canonical plugin hash the decision pins
 * to; `isUpgrade` + `previousApprovedHash` let the surface explain that a
 * previously-approved plugin changed.
 */
export type PluginApprovalContext = {
  pluginId: string;
  approvedHash: string;
  publisherFingerprint?: string;
  trust: PluginApprovalTrust;
  capabilities?: PluginCapabilities;
  isUpgrade: boolean;
  previousApprovedHash?: string;
};

// Discriminated decision — never a bare boolean, so a denial can carry a reason.
export type PluginApprovalDecision = { kind: "approved" } | { kind: "denied"; reason?: string };

export type PluginApprovalResolver = (
  context: PluginApprovalContext,
) => Promise<PluginApprovalDecision>;

// Pinned onto the install record so a later install of the same hash skips the
// prompt. Omitted entirely for exempt (trusted-source/bundled) installs.
export type ApprovedInstallFacts = {
  approvedHash: string;
  approvedAt: string;
  approvedPublisherFingerprint?: string;
};
