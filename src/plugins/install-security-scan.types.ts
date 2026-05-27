export type InstallSafetyOverrides = {
  dangerouslyForceUnsafeInstall?: boolean;
  trustedSourceLinkedOfficialInstall?: boolean;
  /**
   * Operator opt-in to install a plugin that ships no openclaw.plugin.sig
   * sidecar. P1.7: default-deny unsigned installs.
   */
  allowUnsigned?: boolean;
};
