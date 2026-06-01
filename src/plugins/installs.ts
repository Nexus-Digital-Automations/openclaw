import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { PluginInstallRecord } from "../config/types.plugins.js";
import { buildNpmResolutionFields, type NpmSpecResolution } from "../infra/install-source-utils.js";

export type PluginInstallUpdate = PluginInstallRecord & { pluginId: string };

export function buildNpmResolutionInstallFields(
  resolution?: NpmSpecResolution,
): Pick<
  PluginInstallRecord,
  "resolvedName" | "resolvedVersion" | "resolvedSpec" | "integrity" | "shasum" | "resolvedAt"
> {
  return buildNpmResolutionFields(resolution);
}

export function recordPluginInstall(
  cfg: OpenClawConfig,
  update: PluginInstallUpdate,
): OpenClawConfig {
  const { pluginId, ...record } = update;
  const previous = cfg.plugins?.installs?.[pluginId];
  const installs = {
    ...cfg.plugins?.installs,
    [pluginId]: {
      ...previous,
      ...record,
      installedAt: record.installedAt ?? new Date().toISOString(),
      // F.4 — every record written here is an external install (npm/clawhub/
      // git/path/archive; bundled plugins are never recorded). New installs
      // opt into the hard-block capability gate; an explicit update value or a
      // prior stamp wins so a re-record never silently downgrades enforcement.
      capabilityGate: record.capabilityGate ?? previous?.capabilityGate ?? "enforced",
    },
  };

  return {
    ...cfg,
    plugins: {
      ...cfg.plugins,
      installs: {
        ...installs,
        [pluginId]: installs[pluginId],
      },
    },
  };
}
