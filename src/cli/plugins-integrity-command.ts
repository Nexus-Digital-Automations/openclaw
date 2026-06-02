// Owner: plugins/cli. Bridges `openclaw plugins lock` and `openclaw plugins
// verify` to the integrity primitives in src/plugins/skills-lock.{ts,runtime.ts}.
// Reads installed-plugin-index for canonical install paths; emits structured
// errors so the gateway never enables a tampered plugin.

import { defaultRuntime } from "../runtime.js";
import { theme } from "../../packages/terminal-core/src/theme.js";

export type PluginsLockOptions = {
  json?: boolean;
  filePath?: string;
};

export type PluginsVerifyOptions = {
  json?: boolean;
  filePath?: string;
};

/**
 * Hash every installed plugin's files and write the canonical skills.lock.
 *
 * Failure modes: throws when an install record points at a path that does not
 * exist (the index lies); the caller surfaces that as a non-zero exit.
 *
 * @stable
 */
export async function runPluginsLockCommand(opts: PluginsLockOptions = {}): Promise<void> {
  const pathByPluginId = await indexInstallPathsByPluginId();
  if (pathByPluginId.size === 0) {
    defaultRuntime.log("No installed plugins discovered. Nothing to lock.");
    return;
  }
  const { hashPluginFiles, writeSkillsLock } = await import("../plugins/skills-lock.runtime.js");
  const { resolveSkillsLockPath } = await import("../plugins/skills-lock.js");
  const lockPath = opts.filePath ?? resolveSkillsLockPath({});

  const pluginEntries = await Promise.all(
    [...pathByPluginId.entries()]
      .toSorted(([a], [b]) => a.localeCompare(b))
      .map(async ([pluginId, installPath]) => ({
        pluginId,
        version: "0.0.0",
        files: await hashPluginFiles(installPath),
      })),
  );
  await writeSkillsLock(lockPath, { plugins: pluginEntries });
  if (opts.json) {
    defaultRuntime.writeJson({ ok: true, lockPath, plugins: pluginEntries.length });
    return;
  }
  defaultRuntime.log(`Wrote skills.lock with ${pluginEntries.length} plugin(s) to ${lockPath}`);
}

/**
 * Verify every plugin in the lockfile against its on-disk install root.
 *
 * Exits non-zero on the first mismatch; the message names the plugin id and
 * the failing file. Returns silently when no lockfile is present so brand-new
 * workspaces are not blocked.
 *
 * @stable
 */
export async function runPluginsVerifyCommand(opts: PluginsVerifyOptions = {}): Promise<void> {
  const { readSkillsLock, verifyPluginAgainstLock } =
    await import("../plugins/skills-lock.runtime.js");
  const { resolveSkillsLockPath, SkillsLockVerificationError } =
    await import("../plugins/skills-lock.js");
  const lockPath = opts.filePath ?? resolveSkillsLockPath({});
  const lock = await readSkillsLock(lockPath);
  if (!lock) {
    if (opts.json) {
      defaultRuntime.writeJson({ ok: true, status: "no-lockfile", lockPath });
      return;
    }
    defaultRuntime.log(`No skills.lock present at ${lockPath}. Run 'openclaw plugins lock' first.`);
    return;
  }

  const pathByPluginId = await indexInstallPathsByPluginId();
  const failures: Array<{ pluginId: string; error: string }> = [];
  for (const plugin of lock.plugins) {
    const installPath = pathByPluginId.get(plugin.pluginId);
    if (!installPath) {
      failures.push({
        pluginId: plugin.pluginId,
        error: "plugin is in lockfile but not in installed-plugin-index",
      });
      continue;
    }
    try {
      await verifyPluginAgainstLock(installPath, plugin.pluginId, lock);
    } catch (err) {
      if (err instanceof SkillsLockVerificationError) {
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
      `Verified ${params.lock.plugins.length} plugin(s) against ${params.lockPath}`,
    );
    return;
  }
  if (params.json) {
    defaultRuntime.writeJson({ ok: false, status: "drift", failures: params.failures });
    defaultRuntime.exit(2);
    return;
  }
  defaultRuntime.error(
    theme.warn(`skills.lock drift detected (${params.failures.length} plugin(s)):`),
  );
  for (const failure of params.failures) {
    defaultRuntime.error(`  - ${failure.pluginId}: ${failure.error}`);
  }
  defaultRuntime.exit(2);
}

async function indexInstallPathsByPluginId(): Promise<Map<string, string>> {
  const { readPersistedInstalledPluginIndex } =
    await import("../plugins/installed-plugin-index-store.js");
  const index = await readPersistedInstalledPluginIndex({});
  const map = new Map<string, string>();
  if (!index?.installRecords) {
    return map;
  }
  for (const [pluginId, record] of Object.entries(index.installRecords).toSorted(([a], [b]) =>
    a.localeCompare(b),
  )) {
    if (typeof record.installPath === "string" && record.installPath.length > 0) {
      map.set(pluginId, record.installPath);
    }
  }
  return map;
}
