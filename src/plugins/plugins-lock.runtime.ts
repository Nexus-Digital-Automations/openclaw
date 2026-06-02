// Owner: plugins/integrity. Runtime hashing, serialization, and verification
// for `plugins.lock`. Walks plugin source trees, hashes payload bytes with
// SHA-256, and refuses to verify against an unknown lockfile version. Separated
// from `plugins-lock.ts` so the control-plane type surface stays import-light.

import crypto from "node:crypto";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { PLUGIN_SIGNATURE_SIDECAR_FILENAME } from "../security/plugin-signing.js";
import { isContainedRelativePath } from "./lock-path-safety.js";
import {
  PLUGINS_LOCK_VERSION,
  PluginsLockHashMismatchError,
  PluginsLockMissingError,
  PluginsLockMissingFileError,
  PluginsLockUnexpectedFileError,
  PluginsLockUnknownPluginError,
  PluginsLockUnsafePathError,
  type PluginsLock,
  type PluginsLockEntry,
  type PluginsLockPlugin,
} from "./plugins-lock.js";

// Files outside the plugin source payload (npm metadata, build artifacts,
// hidden caches) would otherwise force `openclaw plugins source-lock` reruns
// for changes that do not affect runtime safety. Mirrors skills-lock plus the
// build/output dirs that bundled plugin authoring produces.
const PLUGINS_LOCK_IGNORED_DIRS: ReadonlySet<string> = new Set([
  "node_modules",
  ".git",
  ".turbo",
  ".cache",
  "dist",
  "dist-runtime",
  "build",
  "coverage",
]);
const PLUGINS_LOCK_IGNORED_FILES: ReadonlySet<string> = new Set([
  ".DS_Store",
  ".npmignore",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

export type WritablePluginsLockInput = {
  plugins: readonly PluginsLockPlugin[];
  generatedAtMs?: number;
};

/**
 * Compute the canonical sha256 hex of a file's bytes.
 *
 * Failure modes: throws the underlying ENOENT/EACCES from fs.readFile. Callers
 * inside verifyPluginSourceAgainstLock translate ENOENT into
 * PluginsLockMissingFileError.
 *
 * @stable
 */
export async function hashPluginSourceFile(absPath: string): Promise<string> {
  const bytes = await readFile(absPath);
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * Read and parse the workspace's plugins.lock.
 *
 * Failure modes:
 *   - Returns undefined when the file is absent (first-install workspace).
 *   - Throws PluginsLockMissingError if the JSON is the wrong shape.
 *   - Throws PluginsLockVersionError on unknown version (no silent degrade).
 *
 * @stable
 */
export async function readPluginsLock(lockPath: string): Promise<PluginsLock | undefined> {
  let raw: string;
  try {
    raw = await readFile(lockPath, "utf8");
  } catch (err) {
    if (isNodeErrnoException(err) && err.code === "ENOENT") {
      return undefined;
    }
    throw err;
  }
  const parsed = JSON.parse(raw) as unknown;
  return assertPluginsLockShape(parsed, lockPath);
}

/**
 * Write the workspace's plugins.lock as deterministically-ordered JSON.
 *
 * Plugin entries are sorted by id and file keys are sorted lexicographically so
 * two locks of identical content produce byte-identical files — required by
 * the prompt-cache rules in AGENTS.md and so diffs are readable.
 *
 * @stable
 */
export async function writePluginsLock(
  lockPath: string,
  input: WritablePluginsLockInput,
): Promise<void> {
  const lock: PluginsLock = {
    version: PLUGINS_LOCK_VERSION,
    plugins: canonicalizePlugins(input.plugins),
    generatedAtMs: input.generatedAtMs ?? Date.now(),
  };
  await mkdir(path.dirname(lockPath), { recursive: true });
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
}

/**
 * Walk a plugin source root and produce the canonical {path → entry} map that
 * `writePluginsLock` consumes. Shared with `verifyPluginSourceAgainstLock` so
 * the lock and verify paths never disagree on which files are in scope.
 *
 * @stable
 */
export async function hashPluginSourceTree(
  pluginRoot: string,
): Promise<Readonly<Record<string, PluginsLockEntry>>> {
  const relativePaths = await collectPluginSourceFiles(pluginRoot);
  const entries: Record<string, PluginsLockEntry> = {};
  for (const relativePath of [...relativePaths].toSorted()) {
    const absPath = path.join(pluginRoot, relativePath);
    const fileStat = await stat(absPath);
    entries[relativePath] = {
      sha256: await hashPluginSourceFile(absPath),
      size: fileStat.size,
    };
  }
  return entries;
}

/**
 * Canonical SHA-256 over a plugin's source tree, excluding the signature
 * sidecar (it is written AFTER hashing during signing, so including it would
 * break verification). Single source of truth for the install-signing gate,
 * the `plugins sign` CLI, and the bundled-plugin signer — build-time signing
 * and install-time verification can never disagree on which bytes are covered.
 *
 * @stable
 */
export async function canonicalPluginHashHex(pluginRoot: string): Promise<string> {
  const files = { ...(await hashPluginSourceTree(pluginRoot)) };
  delete (files as Record<string, unknown>)[PLUGIN_SIGNATURE_SIDECAR_FILENAME];
  const canonical = JSON.stringify(files);
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * Verify that `pluginRoot` matches its entry in `lock`.
 *
 * Failure modes: throws the narrowest PluginsLockVerificationError subclass —
 * UnknownPlugin, MissingFile, UnexpectedFile, or HashMismatch. Returns
 * normally only on a full byte-for-byte match.
 *
 * @stable
 */
export async function verifyPluginSourceAgainstLock(
  pluginRoot: string,
  pluginId: string,
  lock: PluginsLock,
): Promise<void> {
  const entry = lock.plugins.find((plugin) => plugin.pluginId === pluginId);
  if (!entry) {
    throw new PluginsLockUnknownPluginError(pluginId);
  }
  const onDisk = await collectPluginSourceFiles(pluginRoot);
  assertNoUnexpectedFiles(pluginId, onDisk, entry.files);
  await assertEveryLockedFileMatches(pluginId, pluginRoot, entry.files);
}

/**
 * Enable-gate convenience: load the lockfile, then verify a single plugin
 * root. Returns silently when no lockfile exists (workspace has opted out);
 * throws PluginsLockVerificationError otherwise. The loader is expected to
 * surface that as a refusal to enable the tampered plugin.
 *
 * @stable
 */
export async function verifyPluginAtLoad(params: {
  pluginRoot: string;
  pluginId: string;
  lockPath: string;
}): Promise<void> {
  const lock = await readPluginsLock(params.lockPath);
  if (!lock) {
    return;
  }
  await verifyPluginSourceAgainstLock(params.pluginRoot, params.pluginId, lock);
}

function isNodeErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && typeof (err as NodeJS.ErrnoException).code === "string";
}

function assertPluginsLockShape(value: unknown, lockPath: string): PluginsLock {
  if (!value || typeof value !== "object") {
    throw new PluginsLockMissingError(lockPath);
  }
  const candidate = value as Partial<PluginsLock>;
  if (candidate.version !== PLUGINS_LOCK_VERSION) {
    throw new PluginsLockVersionError(candidate.version, lockPath);
  }
  if (!Array.isArray(candidate.plugins)) {
    throw new PluginsLockMissingError(lockPath);
  }
  // The lockfile is untrusted on read; its file keys are later path.join'd
  // against the plugin root and stat/hashed (verifyPluginSourceAgainstLock), so
  // an escaping key would become an arbitrary out-of-tree read. Reject the whole
  // lock at this single parse boundary — mirrors skills-lock via the shared
  // isContainedRelativePath guard so the two parsers cannot drift apart.
  for (const plugin of candidate.plugins) {
    const files = (plugin as Partial<PluginsLockPlugin>).files;
    if (!files || typeof files !== "object") {
      continue;
    }
    for (const key of Object.keys(files)) {
      if (!isContainedRelativePath(key)) {
        throw new PluginsLockUnsafePathError(
          (plugin as Partial<PluginsLockPlugin>).pluginId ?? "(unknown)",
          key,
        );
      }
    }
  }
  return candidate as PluginsLock;
}

class PluginsLockVersionError extends Error {
  constructor(observed: unknown, lockPath: string) {
    super(
      `plugins.lock at ${lockPath} has unsupported version ${String(observed)}; expected ${PLUGINS_LOCK_VERSION}`,
    );
    this.name = "PluginsLockVersionError";
  }
}

function canonicalizePlugins(plugins: readonly PluginsLockPlugin[]): readonly PluginsLockPlugin[] {
  return plugins
    .map((plugin) => ({
      pluginId: plugin.pluginId,
      version: plugin.version,
      files: sortRecordKeys(plugin.files),
    }))
    .toSorted((a, b) => a.pluginId.localeCompare(b.pluginId));
}

function sortRecordKeys(
  files: Readonly<Record<string, PluginsLockEntry>>,
): Readonly<Record<string, PluginsLockEntry>> {
  const out: Record<string, PluginsLockEntry> = {};
  for (const key of Object.keys(files).toSorted()) {
    out[key] = files[key];
  }
  return out;
}

async function collectPluginSourceFiles(pluginRoot: string): Promise<Set<string>> {
  const entries = await readdir(pluginRoot, { withFileTypes: true, recursive: true });
  const out = new Set<string>();
  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }
    if (PLUGINS_LOCK_IGNORED_FILES.has(entry.name)) {
      continue;
    }
    const parent = entry.parentPath ?? (entry as unknown as { path: string }).path ?? pluginRoot;
    const relative = path.relative(pluginRoot, path.join(parent, entry.name));
    const posixRelative = relative.split(path.sep).join("/");
    if (isIgnoredByPathSegments(posixRelative)) {
      continue;
    }
    out.add(posixRelative);
  }
  return out;
}

function isIgnoredByPathSegments(posixPath: string): boolean {
  return posixPath.split("/").some((segment) => PLUGINS_LOCK_IGNORED_DIRS.has(segment));
}

function assertNoUnexpectedFiles(
  pluginId: string,
  onDisk: ReadonlySet<string>,
  locked: Readonly<Record<string, PluginsLockEntry>>,
): void {
  for (const relativePath of onDisk) {
    if (!Object.hasOwn(locked, relativePath)) {
      throw new PluginsLockUnexpectedFileError(pluginId, relativePath);
    }
  }
}

async function assertEveryLockedFileMatches(
  pluginId: string,
  pluginRoot: string,
  locked: Readonly<Record<string, PluginsLockEntry>>,
): Promise<void> {
  for (const [relativePath, entry] of Object.entries(locked)) {
    const absPath = path.join(pluginRoot, relativePath);
    let actualSize: number;
    try {
      const fileStat = await stat(absPath);
      actualSize = fileStat.size;
    } catch (err) {
      if (isNodeErrnoException(err) && err.code === "ENOENT") {
        throw new PluginsLockMissingFileError(pluginId, relativePath);
      }
      throw err;
    }
    if (actualSize !== entry.size) {
      throw new PluginsLockHashMismatchError({
        pluginId,
        relativePath,
        expected: entry.sha256,
        actual: await hashPluginSourceFile(absPath),
      });
    }
    const actualHash = await hashPluginSourceFile(absPath);
    if (actualHash !== entry.sha256) {
      throw new PluginsLockHashMismatchError({
        pluginId,
        relativePath,
        expected: entry.sha256,
        actual: actualHash,
      });
    }
  }
}
