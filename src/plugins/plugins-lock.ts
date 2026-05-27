// Owner: plugins/integrity. Locks the byte-level contents of plugin source
// trees (bundled `extensions/` packages plus any explicit external plugin
// roots) so the loader can detect tampering between releases. Mirrors the
// skills-lock pattern but operates on plugin SOURCE rather than installed
// payload paths — the two artifacts coexist in the state directory.

import path from "node:path";
import { resolveStateDir } from "../config/paths.js";

// `plugins.lock` sits next to `plugins/skills.lock` so a workspace's full
// plugin-trust state is inspectable in one directory. Bumping `version` is the
// only breaking change signal — readers refuse unknown versions.
const PLUGINS_LOCK_STORE_PATH = path.join("plugins", "plugins.lock");

export const PLUGINS_LOCK_VERSION = 1 as const;

export type PluginsLockEntry = {
  /** SHA-256 hex of the file at the keyed path, computed via crypto.createHash("sha256"). */
  sha256: string;
  /** Bytes at hash time. Cheap pre-hash drift signal. */
  size: number;
};

export type PluginsLockPlugin = {
  /** Plugin id (directory name under `extensions/` or explicit external id). */
  pluginId: string;
  /** Resolved version at lock time. Defaults to "0.0.0" when no manifest is present. */
  version: string;
  /**
   * POSIX-style paths relative to the plugin's root → entry. Object key order
   * is lexicographic so JSON serialization is deterministic for prompt-cache
   * rules.
   */
  files: Readonly<Record<string, PluginsLockEntry>>;
};

export type PluginsLock = {
  version: typeof PLUGINS_LOCK_VERSION;
  /** Sorted by pluginId ascending for deterministic serialization. */
  plugins: readonly PluginsLockPlugin[];
  /** Wall-clock at write time. Informational only — never used for trust decisions. */
  generatedAtMs: number;
};

export type ResolvePluginsLockPathOptions = {
  env?: NodeJS.ProcessEnv;
  stateDir?: string;
  filePath?: string;
};

export function resolvePluginsLockPath(options: ResolvePluginsLockPathOptions = {}): string {
  if (options.filePath) {
    return options.filePath;
  }
  const env = options.env ?? process.env;
  const stateDir = options.stateDir ?? resolveStateDir(env);
  return path.join(stateDir, PLUGINS_LOCK_STORE_PATH);
}

// Common base so callers can catch the family once, then narrow via instanceof
// to the specific subclass. Same shape as SkillsLockVerificationError so the
// CLI surface can render either lockfile drift uniformly.
export class PluginsLockVerificationError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "PluginsLockVerificationError";
  }
}

export class PluginsLockMissingError extends PluginsLockVerificationError {
  constructor(lockPath: string) {
    super(`plugins.lock not found at ${lockPath}`);
    this.name = "PluginsLockMissingError";
  }
}

export class PluginsLockUnknownPluginError extends PluginsLockVerificationError {
  readonly pluginId: string;
  constructor(pluginId: string) {
    super(`plugin "${pluginId}" has no entry in plugins.lock`);
    this.name = "PluginsLockUnknownPluginError";
    this.pluginId = pluginId;
  }
}

export class PluginsLockMissingFileError extends PluginsLockVerificationError {
  readonly pluginId: string;
  readonly relativePath: string;
  constructor(pluginId: string, relativePath: string) {
    super(
      `plugins.lock lists "${relativePath}" for plugin "${pluginId}" but the file is absent on disk`,
    );
    this.name = "PluginsLockMissingFileError";
    this.pluginId = pluginId;
    this.relativePath = relativePath;
  }
}

export class PluginsLockUnexpectedFileError extends PluginsLockVerificationError {
  readonly pluginId: string;
  readonly relativePath: string;
  constructor(pluginId: string, relativePath: string) {
    super(
      `plugin "${pluginId}" contains "${relativePath}" on disk but plugins.lock has no entry for it`,
    );
    this.name = "PluginsLockUnexpectedFileError";
    this.pluginId = pluginId;
    this.relativePath = relativePath;
  }
}

export class PluginsLockHashMismatchError extends PluginsLockVerificationError {
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
    this.name = "PluginsLockHashMismatchError";
    this.pluginId = params.pluginId;
    this.relativePath = params.relativePath;
    this.expected = params.expected;
    this.actual = params.actual;
  }
}

export {
  hashPluginSourceFile,
  hashPluginSourceTree,
  readPluginsLock,
  verifyPluginAtLoad,
  verifyPluginSourceAgainstLock,
  writePluginsLock,
  type WritablePluginsLockInput,
} from "./plugins-lock.runtime.js";
