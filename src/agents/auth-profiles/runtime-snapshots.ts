import { cloneAuthProfileStore } from "./clone.js";
import { CREDENTIAL_RESIDENCY_IDLE_TTL_MS } from "./constants.js";
import { resolveAuthStorePath } from "./path-resolve.js";
import { emitCredentialResidencyEviction } from "./residency-eviction.js";
import type { AuthProfileStore } from "./types.js";

// lastAccessMs drives idle-residency eviction: an untouched snapshot is dropped
// rather than held for the whole process lifetime (see constants.ts).
type SnapshotEntry = { store: AuthProfileStore; lastAccessMs: number };

const runtimeAuthStoreSnapshots = new Map<string, SnapshotEntry>();

function resolveRuntimeStoreKey(agentDir?: string): string {
  return resolveAuthStorePath(agentDir);
}

// Lazy (no-timer) residency eviction: on access, drop an entry untouched past
// the idle window so idle credentials leave the heap; otherwise refresh its
// last-access stamp and return it. Returning a live entry keeps the
// clone-on-read guarantee — callers never receive this internal object.
function readFreshSnapshotEntry(key: string): SnapshotEntry | undefined {
  const entry = runtimeAuthStoreSnapshots.get(key);
  if (!entry) {
    return undefined;
  }
  const now = Date.now();
  if (now - entry.lastAccessMs >= CREDENTIAL_RESIDENCY_IDLE_TTL_MS) {
    runtimeAuthStoreSnapshots.delete(key);
    emitCredentialResidencyEviction({
      cache: "runtime-snapshot",
      reason: "idle-ttl",
      evictedCount: 1,
    });
    return undefined;
  }
  entry.lastAccessMs = now;
  return entry;
}

export function getRuntimeAuthProfileStoreSnapshot(
  agentDir?: string,
): AuthProfileStore | undefined {
  const entry = readFreshSnapshotEntry(resolveRuntimeStoreKey(agentDir));
  return entry ? cloneAuthProfileStore(entry.store) : undefined;
}

export function hasRuntimeAuthProfileStoreSnapshot(agentDir?: string): boolean {
  return readFreshSnapshotEntry(resolveRuntimeStoreKey(agentDir)) !== undefined;
}

export function hasAnyRuntimeAuthProfileStoreSource(agentDir?: string): boolean {
  const requestedStore = getRuntimeAuthProfileStoreSnapshot(agentDir);
  if (requestedStore && Object.keys(requestedStore.profiles).length > 0) {
    return true;
  }
  if (!agentDir) {
    return false;
  }
  const mainStore = getRuntimeAuthProfileStoreSnapshot();
  return Boolean(mainStore && Object.keys(mainStore.profiles).length > 0);
}

export function replaceRuntimeAuthProfileStoreSnapshots(
  entries: Array<{ agentDir?: string; store: AuthProfileStore }>,
): void {
  runtimeAuthStoreSnapshots.clear();
  const now = Date.now();
  for (const entry of entries) {
    runtimeAuthStoreSnapshots.set(resolveRuntimeStoreKey(entry.agentDir), {
      store: cloneAuthProfileStore(entry.store),
      lastAccessMs: now,
    });
  }
}

export function clearRuntimeAuthProfileStoreSnapshots(): void {
  runtimeAuthStoreSnapshots.clear();
}

export function setRuntimeAuthProfileStoreSnapshot(
  store: AuthProfileStore,
  agentDir?: string,
): void {
  runtimeAuthStoreSnapshots.set(resolveRuntimeStoreKey(agentDir), {
    store: cloneAuthProfileStore(store),
    lastAccessMs: Date.now(),
  });
}
