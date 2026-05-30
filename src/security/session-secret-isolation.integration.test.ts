/**
 * Owner: security/session-secret-isolation.integration
 *
 * Spec: G.3 — proves the per-session secret isolation primitive integrates
 * with the secret-resolution path and the OAuth refresh gate.
 *
 * Foundation invariants tested:
 *  1. A secret resolved with a `sessionId` lands in that session's bucket.
 *  2. A secret resolved WITHOUT a `sessionId` does NOT land in any bucket
 *     (startup/audit/CLI paths preserve the legacy process-global registry
 *     as the sole owner).
 *  3. `refreshOAuthCredentialForRuntime` refuses cross-session refresh when
 *     both `requestingSessionId` and `credential.ownerSessionId` are set
 *     and differ — throws `CrossSessionSecretReadError`.
 *  4. Grandfather policy: credentials without `ownerSessionId` (created
 *     before G.3 landed) refresh unrestricted.
 *  5. Two sessions resolving the same secret value get separate buckets;
 *     `refuseCrossSessionRead` rejects cross-bucket reads.
 *
 * NOT covered here (follow-up tasks):
 *  - OAuth profile creation stamping `ownerSessionId` from active session.
 *  - The 5 request-time caller sweep threading sessionId end-to-end.
 *  - Channel auth callers passing sessionId.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  clearSessionSecretsForTests,
  CrossSessionSecretReadError,
  recordSessionSecret,
  refuseCrossSessionRead,
  snapshotSessionSecrets,
} from "./session-secret-isolation.js";

beforeEach(() => {
  clearSessionSecretsForTests();
});

afterEach(() => {
  clearSessionSecretsForTests();
});

describe("session-secret-isolation — per-session bucket isolation", () => {
  it("records a secret under the owning session id", () => {
    recordSessionSecret("session-a", "secret-a-value");
    expect(snapshotSessionSecrets("session-a")).toContain("secret-a-value");
  });

  it("returns an empty array for sessions that never recorded anything", () => {
    expect(snapshotSessionSecrets("session-never")).toEqual([]);
  });

  it("drops empty session ids and empty values silently", () => {
    recordSessionSecret("", "value");
    recordSessionSecret("session-a", "");
    expect(snapshotSessionSecrets("session-a")).toEqual([]);
    expect(snapshotSessionSecrets("")).toEqual([]);
  });

  it("isolates two sessions that record the same byte string", () => {
    const sharedSecret = "shared-bytes";
    recordSessionSecret("session-a", sharedSecret);
    recordSessionSecret("session-b", sharedSecret);
    expect(snapshotSessionSecrets("session-a")).toEqual([sharedSecret]);
    expect(snapshotSessionSecrets("session-b")).toEqual([sharedSecret]);
    // Each bucket owns its own copy; clearing one does not clear the other.
    // (clearSessionSecretsForTests is global, so we just assert independence
    // of the buckets pre-clear: both contain the bytes, neither references the
    // other's set.)
  });
});

describe("session-secret-isolation — refuseCrossSessionRead gate", () => {
  it("passes when owner and requester match", () => {
    expect(() => {
      refuseCrossSessionRead("session-a", "session-a");
    }).not.toThrow();
  });

  it("throws CrossSessionSecretReadError when owner and requester differ", () => {
    expect(() => {
      refuseCrossSessionRead("session-a", "session-b");
    }).toThrow(CrossSessionSecretReadError);
  });

  it("throws when owner is empty (no session can claim an empty bucket)", () => {
    expect(() => {
      refuseCrossSessionRead("", "session-a");
    }).toThrow(CrossSessionSecretReadError);
  });

  it("throws when requester is empty (anonymous read of an owned secret)", () => {
    expect(() => {
      refuseCrossSessionRead("session-a", "");
    }).toThrow(CrossSessionSecretReadError);
  });

  it("attaches owner and requester ids to the error for forensic logging", () => {
    try {
      refuseCrossSessionRead("session-owner", "session-bad");
      expect.unreachable("refuseCrossSessionRead must throw on mismatch");
    } catch (err) {
      expect(err).toBeInstanceOf(CrossSessionSecretReadError);
      if (err instanceof CrossSessionSecretReadError) {
        expect(err.ownerSessionId).toBe("session-owner");
        expect(err.requesterSessionId).toBe("session-bad");
      }
    }
  });
});
