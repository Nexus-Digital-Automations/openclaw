/**
 * Spec: G.3 per-session secret isolation primitive.
 *
 * Verifies session-A secrets are unreadable from session-B even with the
 * same caller code path, and that cross-session reads throw a typed
 * error rather than silently falling back.
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  CrossSessionSecretReadError,
  clearSessionSecrets,
  clearSessionSecretsForTests,
  recordSessionSecret,
  refuseCrossSessionRead,
  snapshotSessionSecrets,
} from "./session-secret-isolation.js";

afterEach(() => {
  clearSessionSecretsForTests();
});

describe("session-secret-isolation — recordSessionSecret + snapshot", () => {
  it("scopes secrets to the recording session", () => {
    recordSessionSecret("session-a", "secret-A1");
    recordSessionSecret("session-a", "secret-A2");
    recordSessionSecret("session-b", "secret-B1");

    expect(new Set(snapshotSessionSecrets("session-a"))).toEqual(
      new Set(["secret-A1", "secret-A2"]),
    );
    expect(new Set(snapshotSessionSecrets("session-b"))).toEqual(new Set(["secret-B1"]));
  });

  it("returns an empty array for unknown sessions", () => {
    expect(snapshotSessionSecrets("never-seen")).toEqual([]);
  });

  it("returns an empty array for empty sessionId", () => {
    recordSessionSecret("session-a", "secret-A1");
    expect(snapshotSessionSecrets("")).toEqual([]);
  });

  it("silently drops empty inputs", () => {
    recordSessionSecret("", "secret");
    recordSessionSecret("session-a", "");
    expect(snapshotSessionSecrets("session-a")).toEqual([]);
  });

  it("is idempotent on repeat-record (Set-backed)", () => {
    recordSessionSecret("session-a", "secret-A1");
    recordSessionSecret("session-a", "secret-A1");
    recordSessionSecret("session-a", "secret-A1");
    expect(snapshotSessionSecrets("session-a")).toEqual(["secret-A1"]);
  });
});

describe("session-secret-isolation — refuseCrossSessionRead", () => {
  it("returns silently when owner and requester match", () => {
    expect(() => refuseCrossSessionRead("session-a", "session-a")).not.toThrow();
  });

  it("throws CrossSessionSecretReadError when ids differ", () => {
    expect(() => refuseCrossSessionRead("session-a", "session-b")).toThrow(
      CrossSessionSecretReadError,
    );
  });

  it("throws on empty owner id (no implicit shared owner)", () => {
    expect(() => refuseCrossSessionRead("", "session-b")).toThrow(CrossSessionSecretReadError);
  });

  it("throws on empty requester id", () => {
    expect(() => refuseCrossSessionRead("session-a", "")).toThrow(CrossSessionSecretReadError);
  });

  it("error carries both session ids for forensic logging", () => {
    try {
      refuseCrossSessionRead("session-a", "session-b");
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(CrossSessionSecretReadError);
      const typed = err as CrossSessionSecretReadError;
      expect(typed.ownerSessionId).toBe("session-a");
      expect(typed.requesterSessionId).toBe("session-b");
    }
  });
});

describe("session-secret-isolation — clearSessionSecrets (residency eviction)", () => {
  it("evicts the session bucket and returns the evicted count", () => {
    recordSessionSecret("session-a", "secret-A1");
    recordSessionSecret("session-a", "secret-A2");

    expect(clearSessionSecrets("session-a")).toBe(2);
    expect(snapshotSessionSecrets("session-a")).toEqual([]);
  });

  it("returns 0 for an unknown session and for an empty id", () => {
    expect(clearSessionSecrets("never-seen")).toBe(0);
    expect(clearSessionSecrets("")).toBe(0);
  });

  it("evicts only the named session, leaving other buckets intact", () => {
    recordSessionSecret("session-a", "alpha");
    recordSessionSecret("session-b", "beta");

    expect(clearSessionSecrets("session-a")).toBe(1);
    expect(snapshotSessionSecrets("session-a")).toEqual([]);
    expect(snapshotSessionSecrets("session-b")).toEqual(["beta"]);
  });
});

describe("session-secret-isolation — combined scenario", () => {
  it("session-A secrets are unreadable from session-B by enforced refusal", () => {
    recordSessionSecret("session-a", "alpha-credential");

    // Defensive composition: caller asserts ownership before peeking.
    expect(() => refuseCrossSessionRead("session-a", "session-b")).toThrow(
      CrossSessionSecretReadError,
    );

    // And the snapshot for session-B itself returns empty — the data is
    // not just gated by the assertion, it lives in a separate bucket.
    expect(snapshotSessionSecrets("session-b")).toEqual([]);
  });
});
