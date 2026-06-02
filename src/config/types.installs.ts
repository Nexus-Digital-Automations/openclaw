export type InstallRecordBase = {
  source: "npm" | "archive" | "path" | "clawhub" | "git";
  spec?: string;
  sourcePath?: string;
  installPath?: string;
  version?: string;
  resolvedName?: string;
  resolvedVersion?: string;
  resolvedSpec?: string;
  integrity?: string;
  shasum?: string;
  resolvedAt?: string;
  installedAt?: string;
  clawhubUrl?: string;
  clawhubPackage?: string;
  clawhubFamily?: "code-plugin" | "bundle-plugin";
  clawhubChannel?: "official" | "community" | "private";
  artifactKind?: "legacy-zip" | "npm-pack";
  artifactFormat?: "zip" | "tgz";
  npmIntegrity?: string;
  npmShasum?: string;
  npmTarballName?: string;
  clawpackSha256?: string;
  clawpackSpecVersion?: number;
  clawpackManifestSha256?: string;
  clawpackSize?: number;
  gitUrl?: string;
  gitRef?: string;
  gitCommit?: string;
  // F.4 — capability-gate enforcement mode, stamped once at install. "enforced"
  // = new external install subject to the hard-block hook gate; absent or
  // "grandfathered" = warn-mode (bundled + installs predating the gate flip).
  capabilityGate?: "enforced" | "grandfathered";
  // Install-approval pin (Track A). The canonical plugin hash the user approved,
  // when it was approved, and the publisher fingerprint at approval time. On a
  // later install/upgrade the gate re-prompts unless the new hash equals
  // `approvedHash`. Absent for trusted-source/bundled installs (never gated) and
  // for records predating the approval gate.
  approvedHash?: string;
  approvedAt?: string;
  approvedPublisherFingerprint?: string;
};
