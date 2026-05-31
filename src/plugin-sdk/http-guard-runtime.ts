/**
 * Owner: plugin-sdk/http-guard-runtime
 *
 * E.1 — `pluginFetch` wrapper that bounds plugin-driven HTTP egress to
 * the host allowlist declared in the plugin's signed capability manifest.
 * Replaces bare `fetch` calls inside bundled-plugin source trees; the
 * E.2 codemod swaps the call sites onto this subpath.
 *
 * Failure modes (refused, not retried):
 *   - plugin id not registered with the runtime capability cache
 *     (install gate did not run or manifest had no capabilities block)
 *     → HttpAllowlistDeniedError("no declared httpAllowlist")
 *   - target host not in the declared allowlist
 *     → HttpAllowlistDeniedError("host not in declared httpAllowlist")
 *
 * Warn vs strict:
 *   - E.7 lands warn-mode (log + counter, dispatch proceeds) using the
 *     same pattern as C.3 hook-runtime gate.
 *   - E.8 lands strict-enforce after C.6 proves the warn → throw flip
 *     pattern. Until E.7 lands, this module exports the strict-enforce
 *     shape; consumers can wrap it in their own warn-mode adapter
 *     during the rollout window.
 *
 * @stable
 */

import { checkHttpAllowlist, getPluginCapabilities } from "../plugins/capabilities.js";

/**
 * Refused HTTP egress. Callers must surface this as a structured
 * security event rather than catching and retrying — the manifest is
 * authoritative; a refused host is a configuration mismatch the
 * operator should see.
 *
 * @stable
 */
export class HttpAllowlistDeniedError extends Error {
  readonly pluginId: string;
  readonly host: string;
  readonly reason: string;

  constructor(pluginId: string, host: string, reason: string) {
    super(`HTTP egress refused: plugin=${pluginId} host=${host} reason=${reason}`);
    this.name = "HttpAllowlistDeniedError";
    this.pluginId = pluginId;
    this.host = host;
    this.reason = reason;
  }
}

function extractHost(input: string | URL): string {
  if (typeof input === "string") {
    try {
      return new URL(input).host;
    } catch {
      return "";
    }
  }
  return input.host;
}

/**
 * Plugin-facing fetch wrapper. Consults `getPluginCapabilities(pluginId)`
 * and the declared `httpAllowlist` before delegating to global `fetch`.
 * Refuses with `HttpAllowlistDeniedError` on miss.
 *
 * Signature mirrors `fetch` so codemods can swap `fetch(url, init)` →
 * `pluginFetch({pluginId, input: url, init})` mechanically.
 *
 * @stable
 */
export async function pluginFetch(params: {
  pluginId: string;
  input: string | URL;
  init?: RequestInit;
}): Promise<Response> {
  const host = extractHost(params.input);
  const capabilities = getPluginCapabilities(params.pluginId);
  const verdict = checkHttpAllowlist(capabilities, host);
  if (!verdict.ok) {
    throw new HttpAllowlistDeniedError(params.pluginId, host, verdict.reason);
  }
  return await globalThis.fetch(params.input, params.init);
}
