import crypto from "node:crypto";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  SKILLS_LOCK_VERSION,
  SkillsLockHashMismatchError,
  SkillsLockMissingError,
  SkillsLockMissingFileError,
  SkillsLockUnexpectedFileError,
  SkillsLockUnknownPluginError,
  type SkillsLock,
  type SkillsLockEntry,
  type SkillsLockPlugin,
} from "./skills-lock.js";

// Files outside the skill payload (npm metadata, lockfiles, hidden caches)
// would otherwise force `openclaw skills lock` reruns on every install for
// changes that do not affect runtime safety.
const SKILLS_LOCK_IGNORED_DIRS: ReadonlySet<string> = new Set([
  "node_modules",
  ".git",
  ".turbo",
  ".cache",
]);
const SKILLS_LOCK_IGNORED_FILES: ReadonlySet<string> = new Set([
  ".DS_Store",
  ".npmignore",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

export type WritableSkillsLockInput = {
  plugins: readonly SkillsLockPlugin[];
  generatedAtMs?: number;
};

/**
 * Compute the canonical sha256 hex of a file's bytes.
 *
 * Failure modes: throws the underlying ENOENT/EACCES from fs.readFile. Callers
 * inside verifyPluginAgainstLock translate those into SkillsLockMissingFileError.
 *
 * @stable
 */
export async function hashSkillFile(absPath: string): Promise<string> {
  const bytes = await readFile(absPath);
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * Read and parse the workspace's skills.lock.
 *
 * Returns undefined when the lockfile does not exist (a first-install workspace).
 * Throws when the lockfile is present but unparseable or carries an unknown
 * `version` — callers must not silently degrade past these signals.
 *
 * @stable
 */
export async function readSkillsLock(lockPath: string): Promise<SkillsLock | undefined> {
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
  return assertSkillsLockShape(parsed, lockPath);
}

/**
 * Write the workspace's skills.lock as deterministically-ordered JSON.
 *
 * Plugin entries are sorted by id and file keys are sorted lexicographically
 * so two installs with the same content produce byte-identical lockfiles —
 * required so prompt-cache rules in AGENTS.md hold and so diffs are readable.
 *
 * @stable
 */
export async function writeSkillsLock(
  lockPath: string,
  input: WritableSkillsLockInput,
): Promise<void> {
  const lock: SkillsLock = {
    version: SKILLS_LOCK_VERSION,
    plugins: canonicalizePlugins(input.plugins),
    generatedAtMs: input.generatedAtMs ?? Date.now(),
  };
  await mkdir(path.dirname(lockPath), { recursive: true });
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
}

/**
 * Verify that `installedPath` matches its entry in `lock`.
 *
 * Throws the most specific subclass of SkillsLockVerificationError it can:
 * UnknownPlugin, MissingFile, UnexpectedFile, or HashMismatch. Returns
 * normally only on a full match.
 *
 * @stable
 */
export async function verifyPluginAgainstLock(
  installedPath: string,
  pluginId: string,
  lock: SkillsLock,
): Promise<void> {
  const entry = lock.plugins.find((plugin) => plugin.pluginId === pluginId);
  if (!entry) {
    throw new SkillsLockUnknownPluginError(pluginId);
  }
  const onDisk = await collectPluginFiles(installedPath);
  assertNoUnexpectedFiles(pluginId, onDisk, entry.files);
  await assertEveryLockedFileMatches(pluginId, installedPath, entry.files);
}

function isNodeErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && typeof (err as NodeJS.ErrnoException).code === "string";
}

function assertSkillsLockShape(value: unknown, lockPath: string): SkillsLock {
  if (!value || typeof value !== "object") {
    throw new SkillsLockMissingError(lockPath);
  }
  const candidate = value as Partial<SkillsLock>;
  if (candidate.version !== SKILLS_LOCK_VERSION) {
    throw new SkillsLockVersionError(candidate.version, lockPath);
  }
  if (!Array.isArray(candidate.plugins)) {
    throw new SkillsLockMissingError(lockPath);
  }
  return candidate as SkillsLock;
}

class SkillsLockVersionError extends Error {
  constructor(observed: unknown, lockPath: string) {
    super(
      `skills.lock at ${lockPath} has unsupported version ${String(observed)}; expected ${SKILLS_LOCK_VERSION}`,
    );
    this.name = "SkillsLockVersionError";
  }
}

function canonicalizePlugins(plugins: readonly SkillsLockPlugin[]): readonly SkillsLockPlugin[] {
  return plugins
    .map((plugin) => ({
      pluginId: plugin.pluginId,
      version: plugin.version,
      files: sortRecordKeys(plugin.files),
    }))
    .toSorted((a, b) => a.pluginId.localeCompare(b.pluginId));
}

function sortRecordKeys(
  files: Readonly<Record<string, SkillsLockEntry>>,
): Readonly<Record<string, SkillsLockEntry>> {
  const out: Record<string, SkillsLockEntry> = {};
  for (const key of Object.keys(files).toSorted()) {
    out[key] = files[key];
  }
  return out;
}

async function collectPluginFiles(installedPath: string): Promise<Set<string>> {
  const entries = await readdir(installedPath, { withFileTypes: true, recursive: true });
  const out = new Set<string>();
  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }
    if (SKILLS_LOCK_IGNORED_FILES.has(entry.name)) {
      continue;
    }
    const parent = entry.parentPath ?? (entry as unknown as { path: string }).path ?? installedPath;
    const relative = path.relative(installedPath, path.join(parent, entry.name));
    const posixRelative = relative.split(path.sep).join("/");
    if (isIgnoredByPathSegments(posixRelative)) {
      continue;
    }
    out.add(posixRelative);
  }
  return out;
}

function isIgnoredByPathSegments(posixPath: string): boolean {
  return posixPath.split("/").some((segment) => SKILLS_LOCK_IGNORED_DIRS.has(segment));
}

function assertNoUnexpectedFiles(
  pluginId: string,
  onDisk: ReadonlySet<string>,
  locked: Readonly<Record<string, SkillsLockEntry>>,
): void {
  for (const relativePath of onDisk) {
    if (!Object.prototype.hasOwnProperty.call(locked, relativePath)) {
      throw new SkillsLockUnexpectedFileError(pluginId, relativePath);
    }
  }
}

async function assertEveryLockedFileMatches(
  pluginId: string,
  installedPath: string,
  locked: Readonly<Record<string, SkillsLockEntry>>,
): Promise<void> {
  for (const [relativePath, entry] of Object.entries(locked)) {
    const absPath = path.join(installedPath, relativePath);
    let actualSize: number;
    try {
      const fileStat = await stat(absPath);
      actualSize = fileStat.size;
    } catch (err) {
      if (isNodeErrnoException(err) && err.code === "ENOENT") {
        throw new SkillsLockMissingFileError(pluginId, relativePath);
      }
      throw err;
    }
    if (actualSize !== entry.size) {
      throw new SkillsLockHashMismatchError({
        pluginId,
        relativePath,
        expected: entry.sha256,
        actual: await hashSkillFile(absPath),
      });
    }
    const actualHash = await hashSkillFile(absPath);
    if (actualHash !== entry.sha256) {
      throw new SkillsLockHashMismatchError({
        pluginId,
        relativePath,
        expected: entry.sha256,
        actual: actualHash,
      });
    }
  }
}
