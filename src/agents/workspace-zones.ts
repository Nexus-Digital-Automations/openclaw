import os from "node:os";
import path from "node:path";
import { resolveUserPath } from "../utils.js";

// Default untrusted-zone convention. Anything under `~/.openclaw/untrusted/`
// is treated as content the model produced or downloaded — never source for
// trusted skills, always wrapped before reaching the prompt. Resolve via the
// existing user-path helper so XDG / HOME overrides work in tests.
const DEFAULT_UNTRUSTED_ROOT = path.join("~", ".openclaw", "untrusted");

export type WorkspaceZone = "trusted" | "untrusted";

export type WorkspaceZoneOptions = {
  /**
   * Absolute, already-resolved roots. Anything inside these (or equal to them)
   * classifies as untrusted. Test injection point; production defaults below.
   */
  untrustedRoots?: readonly string[];
  env?: NodeJS.ProcessEnv;
  homedir?: () => string;
  /**
   * Whether the filesystem is case-insensitive. Defaults to true on darwin/win32
   * (APFS/HFS+/NTFS), where a case-variant path resolves to the same file and
   * would otherwise dodge the untrusted-zone check. Injectable for tests.
   */
  caseInsensitive?: boolean;
};

type ResolvedZoneConfig = {
  untrustedRoots: readonly string[];
  caseInsensitive: boolean;
};

/**
 * Classify an absolute filesystem path as trusted or untrusted.
 *
 * Fail-safe: relative or empty input classifies as `untrusted` so accidental
 * use of unresolved paths cannot promote model-generated content into the
 * trusted zone. Caller-owned per-request caching is the right scope; this
 * function intentionally has no global cache to keep test isolation simple.
 *
 * @stable
 */
export function classifyZone(absPath: string, options: WorkspaceZoneOptions = {}): WorkspaceZone {
  if (!absPath || !path.isAbsolute(absPath)) {
    return "untrusted";
  }
  const config = resolveZoneConfig(options);
  const normalized = path.resolve(absPath);
  for (const root of config.untrustedRoots) {
    if (isPathInsideOrEqualTo(normalized, root, config.caseInsensitive)) {
      return "untrusted";
    }
  }
  return "trusted";
}

/**
 * Pre-resolved variant for hot paths. Build the config once per request via
 * `resolveWorkspaceZoneConfig`, then pass it to every classifyZone call so the
 * untrusted-root resolution (which touches env + homedir) runs once.
 *
 * @stable
 */
export function classifyZoneWithResolvedConfig(
  absPath: string,
  config: ResolvedZoneConfig,
): WorkspaceZone {
  if (!absPath || !path.isAbsolute(absPath)) {
    return "untrusted";
  }
  const normalized = path.resolve(absPath);
  for (const root of config.untrustedRoots) {
    if (isPathInsideOrEqualTo(normalized, root, config.caseInsensitive)) {
      return "untrusted";
    }
  }
  return "trusted";
}

/**
 * Resolve the zone config once. Use the result with
 * `classifyZoneWithResolvedConfig` on tight loops.
 *
 * @stable
 */
export function resolveWorkspaceZoneConfig(options: WorkspaceZoneOptions = {}): ResolvedZoneConfig {
  return resolveZoneConfig(options);
}

function resolveZoneConfig(options: WorkspaceZoneOptions): ResolvedZoneConfig {
  const caseInsensitive =
    options.caseInsensitive ?? (process.platform === "darwin" || process.platform === "win32");
  if (options.untrustedRoots && options.untrustedRoots.length > 0) {
    return {
      untrustedRoots: options.untrustedRoots.map((root) => path.resolve(root)),
      caseInsensitive,
    };
  }
  const env = options.env ?? process.env;
  const homedir = options.homedir ?? os.homedir;
  const defaultRoot = resolveUserPath(DEFAULT_UNTRUSTED_ROOT, env, homedir);
  return { untrustedRoots: [path.resolve(defaultRoot)], caseInsensitive };
}

function isPathInsideOrEqualTo(child: string, parent: string, caseInsensitive: boolean): boolean {
  // On case-insensitive filesystems a case-variant path (`.../UNTRUSTED/x`)
  // resolves to the same file as `.../untrusted/x`, so fold case before the
  // containment test; otherwise it would classify as trusted and be delivered
  // unwrapped. Linux is case-sensitive — leave paths untouched there.
  const foldedChild = caseInsensitive ? child.toLowerCase() : child;
  const foldedParent = caseInsensitive ? parent.toLowerCase() : parent;
  if (foldedChild === foldedParent) {
    return true;
  }
  const relative = path.relative(foldedParent, foldedChild);
  if (!relative || relative.startsWith("..")) {
    return false;
  }
  return !path.isAbsolute(relative);
}
