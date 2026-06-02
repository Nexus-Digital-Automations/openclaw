/**
 * Owner: plugin-sdk/fs-guard-runtime
 *
 * E.4 — plugin-facing filesystem wrappers that bound plugin reads /
 * writes / directory listings to the named fs scopes the plugin
 * declared in its signed capability manifest. Mirrors the http-guard
 * shape: cache-driven capability lookup, typed refusal error, fail-
 * closed by default with E.7 wiring a warn-mode adapter.
 *
 * Three scope-checked helpers:
 *   - pluginReadFile  ← FsScope "workspace.read" / "skills.read" / "memory.read"
 *   - pluginWriteFile ← FsScope "workspace.write" / "memory.write"
 *   - pluginListDir   ← treated as a read; uses the same read scopes
 *
 * The mapping from absolute path → required FsScope is the caller's
 * responsibility (plugin authors specify which scope each access uses
 * via the `scope` argument). The runtime check is a pure manifest
 * verification; path-to-scope mapping logic stays out of the SDK so
 * future scopes (e.g. "tmp.write") can land without churning every
 * call site.
 *
 * @stable
 */

import { promises as fs } from "node:fs";
import {
  checkFsScope,
  getPluginCapabilities,
  type PluginFsScope,
} from "../plugins/capabilities.js";

/**
 * Refused filesystem access. Callers surface this as a structured
 * security event rather than catching and falling back; the manifest
 * is authoritative.
 *
 * @stable
 */
export class FsScopeDeniedError extends Error {
  readonly pluginId: string;
  readonly scope: PluginFsScope;
  readonly reason: string;

  constructor(pluginId: string, scope: PluginFsScope, reason: string) {
    super(`FS access refused: plugin=${pluginId} scope=${scope} reason=${reason}`);
    this.name = "FsScopeDeniedError";
    this.pluginId = pluginId;
    this.scope = scope;
    this.reason = reason;
  }
}

function assertScopeOrThrow(pluginId: string, scope: PluginFsScope): void {
  const capabilities = getPluginCapabilities(pluginId);
  const verdict = checkFsScope(capabilities, scope);
  if (!verdict.ok) {
    throw new FsScopeDeniedError(pluginId, scope, verdict.reason);
  }
}

/**
 * Read a file as utf8 after asserting the plugin declared the required
 * fs scope. Throws FsScopeDeniedError on miss without touching disk.
 *
 * @stable
 */
export async function pluginReadFile(params: {
  pluginId: string;
  scope: PluginFsScope;
  filePath: string;
}): Promise<string> {
  assertScopeOrThrow(params.pluginId, params.scope);
  return await fs.readFile(params.filePath, "utf8");
}

/**
 * Write a string to a file after asserting the plugin declared the
 * required fs scope. Throws FsScopeDeniedError on miss without
 * touching disk.
 *
 * @stable
 */
export async function pluginWriteFile(params: {
  pluginId: string;
  scope: PluginFsScope;
  filePath: string;
  contents: string;
}): Promise<void> {
  assertScopeOrThrow(params.pluginId, params.scope);
  await fs.writeFile(params.filePath, params.contents, "utf8");
}

/**
 * List directory entries as plain string names after asserting the
 * plugin declared the required (read-side) fs scope. Returns string[]
 * to keep the SDK surface narrow — callers needing Dirent metadata
 * should ask for a separate helper rather than widening this one.
 *
 * @stable
 */
export async function pluginListDir(params: {
  pluginId: string;
  scope: PluginFsScope;
  dirPath: string;
}): Promise<string[]> {
  assertScopeOrThrow(params.pluginId, params.scope);
  return await fs.readdir(params.dirPath);
}
