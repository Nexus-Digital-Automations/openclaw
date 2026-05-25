import path from "node:path";
import { resolveStateDir } from "../config/paths.js";

// `skills.lock` lives next to `plugins/installs.json` (see
// resolveInstalledPluginIndexStorePath) so a workspace's plugin-trust state is
// inspectable in one directory. Bumping `version` is the only breaking change
// signal — readers refuse unknown versions.
const SKILLS_LOCK_STORE_PATH = path.join("plugins", "skills.lock");

export const SKILLS_LOCK_VERSION = 1 as const;

export type SkillsLockEntry = {
  /** SHA-256 hex of the file at the keyed path, computed via crypto.createHash("sha256"). */
  sha256: string;
  /** Bytes at hash time. Cheap pre-hash drift signal. */
  size: number;
};

export type SkillsLockPlugin = {
  /** Plugin id from manifest. Matches InstalledPluginIndexRecord.pluginId. */
  pluginId: string;
  /** Resolved version at lock time. Matches the manifest's packageVersion field. */
  version: string;
  /**
   * POSIX-style paths relative to the plugin's root → entry. Object key order is
   * lexicographic so JSON serialization is deterministic for prompt-cache rules.
   */
  files: Readonly<Record<string, SkillsLockEntry>>;
};

export type SkillsLock = {
  version: typeof SKILLS_LOCK_VERSION;
  /** Sorted by pluginId ascending for deterministic serialization. */
  plugins: readonly SkillsLockPlugin[];
  /** Wall-clock at write time. Informational only — never used for trust decisions. */
  generatedAtMs: number;
};

export type ResolveSkillsLockPathOptions = {
  env?: NodeJS.ProcessEnv;
  stateDir?: string;
  filePath?: string;
};

export function resolveSkillsLockPath(options: ResolveSkillsLockPathOptions = {}): string {
  if (options.filePath) {
    return options.filePath;
  }
  const env = options.env ?? process.env;
  const stateDir = options.stateDir ?? resolveStateDir(env);
  return path.join(stateDir, SKILLS_LOCK_STORE_PATH);
}

// Common base so callers can catch the family once, then narrow via instanceof
// to the specific subclass. Mirrors the FsSafeError discriminator pattern in
// src/infra/fs-safe.ts.
export class SkillsLockVerificationError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "SkillsLockVerificationError";
  }
}

export class SkillsLockMissingError extends SkillsLockVerificationError {
  constructor(lockPath: string) {
    super(`skills.lock not found at ${lockPath}`);
    this.name = "SkillsLockMissingError";
  }
}

export class SkillsLockUnknownPluginError extends SkillsLockVerificationError {
  readonly pluginId: string;
  constructor(pluginId: string) {
    super(`installed plugin "${pluginId}" has no entry in skills.lock`);
    this.name = "SkillsLockUnknownPluginError";
    this.pluginId = pluginId;
  }
}

export class SkillsLockMissingFileError extends SkillsLockVerificationError {
  readonly pluginId: string;
  readonly relativePath: string;
  constructor(pluginId: string, relativePath: string) {
    super(
      `skills.lock lists "${relativePath}" for plugin "${pluginId}" but the file is absent on disk`,
    );
    this.name = "SkillsLockMissingFileError";
    this.pluginId = pluginId;
    this.relativePath = relativePath;
  }
}

export class SkillsLockUnexpectedFileError extends SkillsLockVerificationError {
  readonly pluginId: string;
  readonly relativePath: string;
  constructor(pluginId: string, relativePath: string) {
    super(
      `plugin "${pluginId}" contains "${relativePath}" on disk but skills.lock has no entry for it`,
    );
    this.name = "SkillsLockUnexpectedFileError";
    this.pluginId = pluginId;
    this.relativePath = relativePath;
  }
}

export class SkillsLockHashMismatchError extends SkillsLockVerificationError {
  readonly pluginId: string;
  readonly relativePath: string;
  readonly expected: string;
  readonly actual: string;
  constructor(params: {
    pluginId: string;
    relativePath: string;
    expected: string;
    actual: string;
  }) {
    super(
      `sha256 mismatch for "${params.relativePath}" in plugin "${params.pluginId}": expected ${params.expected}, got ${params.actual}`,
    );
    this.name = "SkillsLockHashMismatchError";
    this.pluginId = params.pluginId;
    this.relativePath = params.relativePath;
    this.expected = params.expected;
    this.actual = params.actual;
  }
}

export {
  hashSkillFile,
  readSkillsLock,
  verifyPluginAgainstLock,
  writeSkillsLock,
  type WritableSkillsLockInput,
} from "./skills-lock.runtime.js";
