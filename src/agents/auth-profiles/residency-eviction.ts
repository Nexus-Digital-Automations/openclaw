// Owner: agents/auth-profiles/residency-eviction
//
// Shared, count-only telemetry for the credential-residency eviction path. The
// loaded-auth-store cache and the runtime snapshot map both drop idle entries
// (CREDENTIAL_RESIDENCY_IDLE_TTL_MS) to shrink how long plaintext credentials
// linger in heap. This module is the single place that records that a drop
// happened — emitting a structured event and bumping a process counter — so the
// security signal is observable WITHOUT ever logging the credentials it exists
// to protect.

import { log } from "./constants.js";

// Which cache produced the eviction — a closed union, not a freeform string, so
// downstream consumers can slice evictions by source without parsing.
export type CredentialCacheName = "loaded-auth-store" | "runtime-snapshot";

let totalResidencyEvictions = 0;

/**
 * Record that `evictedCount` idle credential-cache entries were dropped.
 *
 * Emits `credential.residency.evicted` (count + cache + reason only) and
 * increments the process-wide counter. NEVER receives or logs secret values —
 * callers pass a count, never the store.
 *
 * @stable
 */
export function emitCredentialResidencyEviction(params: {
  cache: CredentialCacheName;
  reason: "idle-ttl";
  evictedCount: number;
}): void {
  if (params.evictedCount <= 0) {
    return;
  }
  totalResidencyEvictions += params.evictedCount;
  log.info("credential.residency.evicted", {
    event: "credential.residency.evicted",
    cache: params.cache,
    reason: params.reason,
    evictedCount: params.evictedCount,
  });
}

/** Process-wide count of credential-cache entries evicted for idle residency. */
export function getCredentialResidencyEvictionCount(): number {
  return totalResidencyEvictions;
}

/** @internal test-only: reset the monotonic counter between cases. */
export function resetCredentialResidencyEvictionCountForTests(): void {
  totalResidencyEvictions = 0;
}
