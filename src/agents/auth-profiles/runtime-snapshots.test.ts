import { afterEach, describe, expect, it, vi } from "vitest";
import { CREDENTIAL_RESIDENCY_IDLE_TTL_MS, log } from "./constants.js";
import {
  getCredentialResidencyEvictionCount,
  resetCredentialResidencyEvictionCountForTests,
} from "./residency-eviction.js";
import {
  clearRuntimeAuthProfileStoreSnapshots,
  getRuntimeAuthProfileStoreSnapshot,
  hasRuntimeAuthProfileStoreSnapshot,
  replaceRuntimeAuthProfileStoreSnapshots,
  setRuntimeAuthProfileStoreSnapshot,
} from "./runtime-snapshots.js";
import type { AuthProfileStore } from "./types.js";

function createStore(access: string): AuthProfileStore {
  return {
    version: 1,
    profiles: {
      "openai:default": {
        type: "oauth",
        provider: "openai",
        access,
        refresh: `refresh-${access}`,
        expires: Date.now() + 60_000,
        accountId: "acct-1",
      },
    },
    order: {
      openai: ["openai:default"],
    },
    usageStats: {
      "openai:default": {
        lastUsed: 1,
      },
    },
  };
}

function expectOpenAICodexSnapshotCredential(
  store: AuthProfileStore | undefined,
  params: { access: string; refresh?: string },
) {
  const credential = store?.profiles["openai:default"];
  expect(credential?.type).toBe("oauth");
  if (credential?.type !== "oauth") {
    throw new Error("Expected OpenAI Codex OAuth credential snapshot");
  }
  expect(credential.provider).toBe("openai");
  expect(credential.access).toBe(params.access);
  if (params.refresh) {
    expect(credential.refresh).toBe(params.refresh);
  }
}

describe("runtime auth profile snapshots", () => {
  it("isolates set/get/replace snapshot mutations without structuredClone", () => {
    const structuredCloneSpy = vi.spyOn(globalThis, "structuredClone");
    const agentDir = "/tmp/openclaw-auth-runtime-snapshot-agent";
    try {
      const stored = createStore("access-1");
      setRuntimeAuthProfileStoreSnapshot(stored, agentDir);
      stored.profiles["openai:default"].provider = "mutated";
      stored.order!["openai"].push("mutated");

      const first = getRuntimeAuthProfileStoreSnapshot(agentDir);
      expectOpenAICodexSnapshotCredential(first, { access: "access-1" });
      expect(first?.order?.["openai"]).toEqual(["openai:default"]);

      first!.profiles["openai:default"].provider = "mutated-again";
      first!.usageStats!["openai:default"].lastUsed = 99;

      const second = getRuntimeAuthProfileStoreSnapshot(agentDir);
      expectOpenAICodexSnapshotCredential(second, { access: "access-1" });
      expect(second?.usageStats?.["openai:default"]?.lastUsed).toBe(1);

      const replacement = createStore("access-2");
      replaceRuntimeAuthProfileStoreSnapshots([{ agentDir, store: replacement }]);
      const replacementCredential = replacement.profiles["openai:default"];
      expect(replacementCredential?.type).toBe("oauth");
      if (replacementCredential?.type === "oauth") {
        replacementCredential.access = "mutated-replacement";
      }

      const replaced = getRuntimeAuthProfileStoreSnapshot(agentDir);
      expectOpenAICodexSnapshotCredential(replaced, {
        access: "access-2",
        refresh: "refresh-access-2",
      });
      expect(structuredCloneSpy).not.toHaveBeenCalled();
    } finally {
      structuredCloneSpy.mockRestore();
      clearRuntimeAuthProfileStoreSnapshots();
    }
  });
});

describe("runtime auth profile snapshot residency eviction", () => {
  const agentDir = "/tmp/openclaw-auth-runtime-residency-agent";

  afterEach(() => {
    vi.useRealTimers();
    clearRuntimeAuthProfileStoreSnapshots();
    resetCredentialResidencyEvictionCountForTests();
    vi.restoreAllMocks();
  });

  it("evicts an idle snapshot once untouched past the residency window", () => {
    vi.useFakeTimers();
    setRuntimeAuthProfileStoreSnapshot(createStore("access-1"), agentDir);

    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS);

    expect(getRuntimeAuthProfileStoreSnapshot(agentDir)).toBeUndefined();
    expect(hasRuntimeAuthProfileStoreSnapshot(agentDir)).toBe(false);
    expect(getCredentialResidencyEvictionCount()).toBe(1);
  });

  it("keeps an actively-read snapshot resident (idle clock, not age)", () => {
    vi.useFakeTimers();
    setRuntimeAuthProfileStoreSnapshot(createStore("access-1"), agentDir);

    // Two reads each inside the idle window, but their sum exceeds it: an
    // age-based bound would have evicted; the idle bound must not.
    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS * 0.6);
    expectOpenAICodexSnapshotCredential(getRuntimeAuthProfileStoreSnapshot(agentDir), {
      access: "access-1",
    });
    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS * 0.6);

    expectOpenAICodexSnapshotCredential(getRuntimeAuthProfileStoreSnapshot(agentDir), {
      access: "access-1",
    });
    expect(getCredentialResidencyEvictionCount()).toBe(0);
  });

  it("leaves an already-returned clone intact when the entry later evicts", () => {
    vi.useFakeTimers();
    setRuntimeAuthProfileStoreSnapshot(createStore("access-1"), agentDir);

    const handed = getRuntimeAuthProfileStoreSnapshot(agentDir);
    expectOpenAICodexSnapshotCredential(handed, { access: "access-1" });

    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS);
    expect(getRuntimeAuthProfileStoreSnapshot(agentDir)).toBeUndefined();

    // The clone handed out earlier is decoupled from the evicted Map entry.
    expectOpenAICodexSnapshotCredential(handed, { access: "access-1" });
  });

  it("never logs credential values in the eviction event", () => {
    vi.useFakeTimers();
    const infoSpy = vi.spyOn(log, "info");
    setRuntimeAuthProfileStoreSnapshot(createStore("access-1"), agentDir);

    vi.advanceTimersByTime(CREDENTIAL_RESIDENCY_IDLE_TTL_MS);
    expect(getRuntimeAuthProfileStoreSnapshot(agentDir)).toBeUndefined();

    const evictionCalls = infoSpy.mock.calls.filter(
      ([message]) => message === "credential.residency.evicted",
    );
    expect(evictionCalls).toHaveLength(1);
    const serialized = JSON.stringify(evictionCalls[0]);
    expect(serialized).not.toContain("access-1");
    expect(serialized).not.toContain("refresh-access-1");
  });
});
