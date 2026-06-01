import { afterEach, describe, expect, it, vi } from "vitest";
import { CREDENTIAL_RESIDENCY_IDLE_TTL_MS, EXTERNAL_CLI_SYNC_TTL_MS, log } from "./constants.js";
import {
  getCredentialResidencyEvictionCount,
  resetCredentialResidencyEvictionCountForTests,
} from "./residency-eviction.js";
import {
  clearLoadedAuthStoreCache,
  readCachedAuthProfileStore,
  writeCachedAuthProfileStore,
} from "./store-cache.js";
import type { AuthProfileStore } from "./types.js";

const AUTH_PATH = "/tmp/openclaw-auth-store-cache.json";

function createStore(access: string): AuthProfileStore {
  return {
    version: 1,
    profiles: {
      "openai-codex:default": {
        type: "oauth",
        provider: "openai-codex",
        access,
        refresh: `refresh-${access}`,
        expires: Date.now() + 60_000,
        accountId: "acct-1",
      },
    },
    order: { "openai-codex": ["openai-codex:default"] },
    usageStats: { "openai-codex:default": { lastUsed: 1 } },
  };
}

function write(access: string, mtimes: { authMtimeMs: number; stateMtimeMs: number }): void {
  writeCachedAuthProfileStore({
    authPath: AUTH_PATH,
    authMtimeMs: mtimes.authMtimeMs,
    stateMtimeMs: mtimes.stateMtimeMs,
    store: createStore(access),
  });
}

function read(mtimes: { authMtimeMs: number; stateMtimeMs: number }): AuthProfileStore | null {
  return readCachedAuthProfileStore({
    authPath: AUTH_PATH,
    authMtimeMs: mtimes.authMtimeMs,
    stateMtimeMs: mtimes.stateMtimeMs,
  });
}

const MTIMES = { authMtimeMs: 10, stateMtimeMs: 20 };

describe("loaded auth store cache residency eviction", () => {
  afterEach(() => {
    vi.useRealTimers();
    clearLoadedAuthStoreCache();
    resetCredentialResidencyEvictionCountForTests();
    vi.restoreAllMocks();
  });

  it("evicts an idle store once untouched past the residency window", () => {
    vi.useFakeTimers();
    write("access-1", MTIMES);

    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS);

    expect(read(MTIMES)).toBeNull();
    expect(getCredentialResidencyEvictionCount()).toBe(1);
  });

  it("reloads transparently after an eviction (re-warm restores a hit)", () => {
    vi.useFakeTimers();
    write("access-1", MTIMES);
    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS);
    expect(read(MTIMES)).toBeNull();

    write("access-2", MTIMES);
    const reloaded = read(MTIMES);
    expect(reloaded?.profiles["openai-codex:default"]?.type).toBe("oauth");
    const credential = reloaded?.profiles["openai-codex:default"];
    expect(credential?.type === "oauth" ? credential.access : undefined).toBe("access-2");
  });

  it("still invalidates on mtime change without counting a residency eviction", () => {
    vi.useFakeTimers();
    write("access-1", MTIMES);

    // Within the idle window, a changed mtime is a freshness miss, not a
    // residency eviction — the counter must stay untouched.
    expect(read({ authMtimeMs: 11, stateMtimeMs: 20 })).toBeNull();
    expect(getCredentialResidencyEvictionCount()).toBe(0);
  });

  it("still applies the external-sync age bound ahead of residency eviction", () => {
    vi.useFakeTimers();
    write("access-1", MTIMES);

    // External-sync expiry (15m) precedes the residency check (5m). Advancing
    // past it returns null via the sync bound, not via an eviction.
    vi.advanceTimersByTime(EXTERNAL_CLI_SYNC_TTL_MS);
    expect(read(MTIMES)).toBeNull();
    expect(getCredentialResidencyEvictionCount()).toBe(0);
  });

  it("never logs credential values in the eviction event", () => {
    vi.useFakeTimers();
    const infoSpy = vi.spyOn(log, "info");
    write("access-1", MTIMES);

    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS);
    expect(read(MTIMES)).toBeNull();

    const evictionCalls = infoSpy.mock.calls.filter(
      ([message]) => message === "credential.residency.evicted",
    );
    expect(evictionCalls).toHaveLength(1);
    const serialized = JSON.stringify(evictionCalls[0]);
    expect(serialized).not.toContain("access-1");
    expect(serialized).not.toContain("refresh-access-1");
  });
});
