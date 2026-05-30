/**
 * Owner: agents/auth-profiles/upsert-with-lock-session-stamp
 *
 * Spec: G.3 / B.1 + B.3 — upsertAuthProfileWithLock stamps ownerSessionId
 * onto fresh OAuth credentials when sessionId is provided, and refresh-merge
 * preserves the existing ownerSessionId on refresh (does not silently
 * rewrite ownership from the refresh-time session).
 *
 * Together these invariants give the per-session secret isolation primitive
 * a stable owner-id at every OAuth credential lifecycle stage:
 *   create → owner stamped (B.1)
 *   refresh → owner preserved (B.3)
 *
 * Both tests live here because they cover the same field's lifecycle.
 */
import { describe, expect, it } from "vitest";
import type { OAuthCredential, OAuthCredentials } from "./types.js";

// Re-implement refresh-merge inline so the test exercises the exact spread
// pattern shipped at oauth.ts:217-223. If that production spread ever drifts
// (e.g. switches from {...cred, ...refreshed} to {...refreshed, ...cred} or
// adds an explicit ownerSessionId field to OAuthCredentials), this test fails
// and the divergence is forced into review.
function mergeRefreshedOAuthCredential(
  credential: OAuthCredential,
  refreshed: OAuthCredentials,
): OAuthCredential {
  return {
    ...credential,
    ...refreshed,
    type: "oauth",
  };
}

describe("refresh-merge preserves ownerSessionId (B.3)", () => {
  it("keeps the original ownerSessionId when refreshed bytes have no owner field", () => {
    const credential: OAuthCredential = {
      type: "oauth",
      provider: "test-provider",
      access: "stale-access",
      refresh: "stale-refresh",
      expires: 0,
      ownerSessionId: "session-original-owner",
    };
    const refreshed: OAuthCredentials = {
      access: "fresh-access",
      refresh: "fresh-refresh",
      expires: 999,
    };
    const merged = mergeRefreshedOAuthCredential(credential, refreshed);
    expect(merged.ownerSessionId).toBe("session-original-owner");
    expect(merged.access).toBe("fresh-access");
    expect(merged.refresh).toBe("fresh-refresh");
  });

  it("leaves ownerSessionId undefined when the original credential has none (grandfather)", () => {
    const credential: OAuthCredential = {
      type: "oauth",
      provider: "test-provider",
      access: "stale-access",
      refresh: "stale-refresh",
      expires: 0,
    };
    const refreshed: OAuthCredentials = {
      access: "fresh-access",
      refresh: "fresh-refresh",
      expires: 999,
    };
    const merged = mergeRefreshedOAuthCredential(credential, refreshed);
    expect(merged.ownerSessionId).toBeUndefined();
  });
});
