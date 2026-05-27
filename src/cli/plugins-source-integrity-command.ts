// Owner: plugins/cli. Bridges `openclaw plugins source-lock` and
// `openclaw plugins source-verify` to the integrity primitives in
// src/plugins/plugins-lock.{ts,runtime.ts}. Walks the bundled-plugins source
// tree (`extensions/`) and external plugin roots passed via --root, hashes
// each plugin's source files, and emits drift as non-zero exit so CI catches
// tampering before the loader enables a plugin.

import { readdir, stat } from "node:fs/promises";
import path from "node:path";
import { defaultRuntime } from "../runtime.js";
import { theme } from "../terminal/theme.js";

export type PluginsSourceLockOptions = {
  json?: boolean;
  filePath?: string;
  dryRun?: boolean;
  roots?: readonly string[];
};

export type PluginsSourceVerifyOptions = {
  json?: boolean;
  filePath?: string;
  roots?: readonly string[];
};

/**
 * Hash every discovered plugin source tree and write the canonical
 * plugins.lock. Honors --dry-run by emitting the would-be lockfile to stdout
 * without touching disk.
 *
 * Failure modes: throws if a passed --root does not resolve to a directory or
 * if hashing a plugin file fails (e.g. permission denied). Both surface as
 * non-zero exits in the caller.
 *
 * @stable
 */
export async function runPluginsSourceLockCommand(
  opts: PluginsSourceLockOptions = {},
): Promise<void> {
  const pluginRoots = await discoverPluginRoots(opts.roots);
  if (pluginRoots.length === 0) {
    defaultRuntime.log("No plugin source trees discovered. Nothing to lock.");
    return;
  }
  const { hashPluginSourceTree, writePluginsLock } =
    await import("../plugins/plugins-lock.runtime.js");
  const { resolvePluginsLockPath, PLUGINS_LOCK_VERSION } =
    await import("../plugins/plugins-lock.js");
  const lockPath = opts.filePath ?? resolvePluginsLockPath({});

  const pluginEntries = await Promise.all(
    pluginRoots.map(async ({ pluginId, rootPath }) => ({
      pluginId,
      version: await readPluginVersionOrFallback(rootPath),
      files: await hashPluginSourceTree(rootPath),
    })),
  );

  if (opts.dryRun) {
    const preview = {
      version: PLUGINS_LOCK_VERSION,
      plugins: pluginEntries.toSorted((a, b) => a.pluginId.localeCompare(b.pluginId)),
    };
    defaultRuntime.writeJson(preview);
    return;
  }

  await writePluginsLock(lockPath, { plugins: pluginEntries });
  if (opts.json) {
    defaultRuntime.writeJson({ ok: true, lockPath, plugins: pluginEntries.length });
    return;
  }
  defaultRuntime.log(`Wrote plugins.lock with ${pluginEntries.length} plugin(s) to ${lockPath}`);
}

/**
 * Verify every plugin in plugins.lock against its on-disk source tree.
 *
 * Failure modes: exits non-zero with a structured diff on the first mismatch
 * (missing file, unexpected file, hash drift). Returns silently when no
 * lockfile is present so brand-new workspaces are not blocked.
 *
 * @stable
 */
export async function runPluginsSourceVerifyCommand(
  opts: PluginsSourceVerifyOptions = {},
): Promise<void> {
  const { readPluginsLock, verifyPluginSourceAgainstLock } =
    await import("../plugins/plugins-lock.runtime.js");
  const { resolvePluginsLockPath, PluginsLockVerificationError } =
    await import("../plugins/plugins-lock.js");
  const lockPath = opts.filePath ?? resolvePluginsLockPath({});
  const lock = await readPluginsLock(lockPath);
  if (!lock) {
    if (opts.json) {
      defaultRuntime.writeJson({ ok: true, status: "no-lockfile", lockPath });
      return;
    }
    defaultRuntime.log(
      `No plugins.lock present at ${lockPath}. Run 'openclaw plugins source-lock' first.`,
    );
    return;
  }

  const pluginRoots = await discoverPluginRoots(opts.roots);
  const rootByPluginId = new Map(pluginRoots.map((entry) => [entry.pluginId, entry.rootPath]));
  const failures: Array<{ pluginId: string; error: string }> = [];
  for (const plugin of lock.plugins) {
    const rootPath = rootByPluginId.get(plugin.pluginId);
    if (!rootPath) {
      failures.push({
        pluginId: plugin.pluginId,
        error: "plugin is in lockfile but its source tree was not found on disk",
      });
      continue;
    }
    try {
      await verifyPluginSourceAgainstLock(rootPath, plugin.pluginId, lock);
    } catch (err) {
      if (err instanceof PluginsLockVerificationError) {
        failures.push({ pluginId: plugin.pluginId, error: err.message });
        continue;
      }
      throw err;
    }
  }
  reportVerifyOutcome({ failures, lock, lockPath, json: opts.json });
}

function reportVerifyOutcome(params: {
  failures: ReadonlyArray<{ pluginId: string; error: string }>;
  lock: { plugins: ReadonlyArray<unknown> };
  lockPath: string;
  json?: boolean;
}): void {
  if (params.failures.length === 0) {
    if (params.json) {
      defaultRuntime.writeJson({
        ok: true,
        status: "verified",
        plugins: params.lock.plugins.length,
      });
      return;
    }
    defaultRuntime.log(
      `Verified ${params.lock.plugins.length} plugin source tree(s) against ${params.lockPath}`,
    );
    return;
  }
  if (params.json) {
    defaultRuntime.writeJson({ ok: false, status: "drift", failures: params.failures });
    defaultRuntime.exit(2);
    return;
  }
  defaultRuntime.error(
    theme.warn(`plugins.lock drift detected (${params.failures.length} plugin(s)):`),
  );
  for (const failure of params.failures) {
    defaultRuntime.error(`  - ${failure.pluginId}: ${failure.error}`);
  }
  defaultRuntime.exit(2);
}

type DiscoveredPluginRoot = { pluginId: string; rootPath: string };

async function discoverPluginRoots(
  explicitRoots?: readonly string[],
): Promise<readonly DiscoveredPluginRoot[]> {
  if (explicitRoots && explicitRoots.length > 0) {
    return Promise.all(
      explicitRoots.map(async (raw) => {
        const rootPath = path.resolve(raw);
        const info = await stat(rootPath);
        if (!info.isDirectory()) {
          throw new Error(`--root must point at a directory: ${raw}`);
        }
        return { pluginId: path.basename(rootPath), rootPath };
      }),
    );
  }
  const { resolveBundledPluginsDir } = await import("../plugins/bundled-dir.js");
  const bundledRoot = resolveBundledPluginsDir();
  if (!bundledRoot) {
    return [];
  }
  return listSubdirectoriesAsPlugins(bundledRoot);
}

async function listSubdirectoriesAsPlugins(
  bundledRoot: string,
): Promise<readonly DiscoveredPluginRoot[]> {
  const entries = await readdir(bundledRoot, { withFileTypes: true });
  const out: DiscoveredPluginRoot[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith(".")) {
      continue;
    }
    out.push({ pluginId: entry.name, rootPath: path.join(bundledRoot, entry.name) });
  }
  return out.toSorted((a, b) => a.pluginId.localeCompare(b.pluginId));
}

async function readPluginVersionOrFallback(rootPath: string): Promise<string> {
  // Manifest validation (P1.4) owns version policy. plugins.lock records what
  // it can read here; absence of package.json is an expected control-plane
  // state, not an integrity failure, so ENOENT is the one error we accept.
  const { readFile } = await import("node:fs/promises");
  let raw: string;
  try {
    raw = await readFile(path.join(rootPath, "package.json"), "utf8");
  } catch (err) {
    if (err instanceof Error && (err as NodeJS.ErrnoException).code === "ENOENT") {
      return "0.0.0";
    }
    throw err;
  }
  const parsed = JSON.parse(raw) as { version?: unknown };
  if (typeof parsed.version === "string" && parsed.version.length > 0) {
    return parsed.version;
  }
  return "0.0.0";
}
