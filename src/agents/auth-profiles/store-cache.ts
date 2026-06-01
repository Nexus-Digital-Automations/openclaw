import { cloneAuthProfileStore } from "./clone.js";
import { CREDENTIAL_RESIDENCY_IDLE_TTL_MS, EXTERNAL_CLI_SYNC_TTL_MS } from "./constants.js";
import { emitCredentialResidencyEviction } from "./residency-eviction.js";
import type { AuthProfileStore } from "./types.js";

const loadedAuthStoreCache = new Map<
  string,
  {
    authMtimeMs: number | null;
    stateMtimeMs: number | null;
    syncedAtMs: number;
    // Last read time — drives idle-residency eviction (constants.ts), separate
    // from syncedAtMs which bounds external-CLI sync freshness.
    lastAccessMs: number;
    store: AuthProfileStore;
  }
>();

export function readCachedAuthProfileStore(params: {
  authPath: string;
  authMtimeMs: number | null;
  stateMtimeMs: number | null;
}): AuthProfileStore | null {
  const cached = loadedAuthStoreCache.get(params.authPath);
  if (
    !cached ||
    cached.authMtimeMs !== params.authMtimeMs ||
    cached.stateMtimeMs !== params.stateMtimeMs
  ) {
    return null;
  }
  if (Date.now() - cached.syncedAtMs >= EXTERNAL_CLI_SYNC_TTL_MS) {
    return null;
  }
  // Additive residency bound: drop a store untouched past the idle window so
  // plaintext credentials don't linger in heap, then force a transparent
  // reload from disk (callers treat null as a cold miss).
  if (Date.now() - cached.lastAccessMs >= CREDENTIAL_RESIDENCY_IDLE_TTL_MS) {
    loadedAuthStoreCache.delete(params.authPath);
    emitCredentialResidencyEviction({
      cache: "loaded-auth-store",
      reason: "idle-ttl",
      evictedCount: 1,
    });
    return null;
  }
  cached.lastAccessMs = Date.now();
  return cloneAuthProfileStore(cached.store);
}

export function writeCachedAuthProfileStore(params: {
  authPath: string;
  authMtimeMs: number | null;
  stateMtimeMs: number | null;
  store: AuthProfileStore;
}): void {
  const now = Date.now();
  loadedAuthStoreCache.set(params.authPath, {
    authMtimeMs: params.authMtimeMs,
    stateMtimeMs: params.stateMtimeMs,
    syncedAtMs: now,
    lastAccessMs: now,
    store: cloneAuthProfileStore(params.store),
  });
}

export function clearLoadedAuthStoreCache(): void {
  loadedAuthStoreCache.clear();
}
