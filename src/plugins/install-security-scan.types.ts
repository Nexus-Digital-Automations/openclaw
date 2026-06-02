export type InstallSafetyOverrides = {
  dangerouslyForceUnsafeInstall?: boolean;
  trustedSourceLinkedOfficialInstall?: boolean;
  /**
   * Operator opt-in to install a plugin that ships no openclaw.plugin.sig
   * sidecar. P1.7: default-deny unsigned installs.
   */
  allowUnsigned?: boolean;
  /**
   * Track A: skip the interactive install-approval prompt and treat the install
   * as approved (`--yes`, or programmatic operator-initiated installs). The
   * approval is still recorded/pinned. Does NOT bypass signing/scan gates.
   */
  assumeApproved?: boolean;
};
