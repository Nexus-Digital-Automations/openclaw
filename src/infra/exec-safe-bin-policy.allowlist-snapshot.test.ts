import { describe, expect, it } from "vitest";
import { DEFAULT_SAFE_BINS, SAFE_BIN_PROFILE_FIXTURES } from "./exec-safe-bin-policy.js";

// Locks the exact shape of the safe-bin allowlist + per-bin denied/allowed-flag
// surface. Any change (adding a bin, removing a denied flag, widening
// positional bounds) requires explicit snapshot update — AGENTS.md forbids
// silencing snapshot drift without owner approval, so PR review sees the diff.

type StableProfile = {
  minPositional: number | null;
  maxPositional: number | null;
  allowedValueFlags: string[];
  deniedFlags: string[];
};

function stabilizeFixtures(): Record<string, StableProfile> {
  const out: Record<string, StableProfile> = {};
  for (const binName of Object.keys(SAFE_BIN_PROFILE_FIXTURES).toSorted()) {
    const fixture = SAFE_BIN_PROFILE_FIXTURES[binName];
    out[binName] = {
      minPositional: fixture.minPositional ?? null,
      maxPositional: fixture.maxPositional ?? null,
      allowedValueFlags: (fixture.allowedValueFlags ?? []).toSorted(),
      deniedFlags: (fixture.deniedFlags ?? []).toSorted(),
    };
  }
  return out;
}

describe("exec-safe-bin policy allowlist snapshot", () => {
  it("locks DEFAULT_SAFE_BINS — owner approval required to change", () => {
    const sortedBins = DEFAULT_SAFE_BINS.toSorted();
    expect(sortedBins).toMatchSnapshot("default-safe-bins");
  });

  it("locks per-bin policy fixtures — owner approval required to change", () => {
    expect(stabilizeFixtures()).toMatchSnapshot("safe-bin-profile-fixtures");
  });
});
