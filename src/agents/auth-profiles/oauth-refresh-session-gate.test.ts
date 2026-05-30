/**
 * Owner: agents/auth-profiles/oauth-refresh-session-gate
 *
 * Spec: G.3 — cross-session refresh refuse gate at the refreshOAuthCredential
 * entry point. The gate moved here (A.1) so every refresh caller inherits it,
 * not just the runtime wrapper.
 *
 * Invariants:
 *  - Mismatched requesting/owner session IDs throw CrossSessionSecretReadError
 *    BEFORE any plugin / SDK / endpoint call is attempted.
 *  - Matching session IDs proceed past the gate to the refresh chain.
 *  - Missing requestingSessionId OR missing credential.ownerSessionId is the
 *    grandfather policy — refresh proceeds unrestricted.
 *  - Empty-string requestingSessionId is treated as "set but invalid" — the
 *    refuse helper rejects it explicitly per session-secret-isolation contract.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("../../plugins/provider-runtime.runtime.js", () => ({
  formatProviderAuthProfileApiKeyWithPlugin: vi.fn(async () => null),
  refreshProviderOAuthCredentialWithPlugin: vi.fn(async () => null),
}));

vi.mock("@earendil-works/pi-ai/oauth", () => ({
  getOAuthApiKey: vi.fn(async () => null),
  getOAuthProviders: vi.fn(() => []),
}));

import { CrossSessionSecretReadError } from "../../security/session-secret-isolation.js";
import { refreshOAuthCredentialForRuntime } from "./oauth.js";
import type { OAuthCredential } from "./types.js";

function makeCredential(overrides: Partial<OAuthCredential> = {}): OAuthCredential {
  return {
    type: "oauth",
    provider: "test-provider",
    access: "test-access",
    refresh: "test-refresh",
    expires: 0,
    ...overrides,
  };
}

describe("refreshOAuthCredentialForRuntime — G.3 cross-session gate", () => {
  it("throws CrossSessionSecretReadError when requesting session differs from owner", async () => {
    const credential = makeCredential({ ownerSessionId: "session-owner" });
    await expect(
      refreshOAuthCredentialForRuntime({
        credential,
        requestingSessionId: "session-attacker",
      }),
    ).rejects.toBeInstanceOf(CrossSessionSecretReadError);
  });

  it("attaches owner + requester ids to the thrown error for forensic logging", async () => {
    const credential = makeCredential({ ownerSessionId: "session-owner" });
    try {
      await refreshOAuthCredentialForRuntime({
        credential,
        requestingSessionId: "session-attacker",
      });
      expect.unreachable("expected CrossSessionSecretReadError");
    } catch (err) {
      expect(err).toBeInstanceOf(CrossSessionSecretReadError);
      if (err instanceof CrossSessionSecretReadError) {
        expect(err.ownerSessionId).toBe("session-owner");
        expect(err.requesterSessionId).toBe("session-attacker");
      }
    }
  });

  it("proceeds past the gate when requesting session matches owner", async () => {
    const credential = makeCredential({ ownerSessionId: "session-shared" });
    const result = await refreshOAuthCredentialForRuntime({
      credential,
      requestingSessionId: "session-shared",
    });
    expect(result).toBeNull();
  });

  it("grandfather: proceeds when credential has no ownerSessionId (pre-G.3 profile)", async () => {
    const credential = makeCredential();
    expect(credential.ownerSessionId).toBeUndefined();
    const result = await refreshOAuthCredentialForRuntime({
      credential,
      requestingSessionId: "session-anything",
    });
    expect(result).toBeNull();
  });

  it("grandfather: proceeds when caller passes no requestingSessionId", async () => {
    const credential = makeCredential({ ownerSessionId: "session-owner" });
    const result = await refreshOAuthCredentialForRuntime({ credential });
    expect(result).toBeNull();
  });

  it("rejects empty requestingSessionId when owner is set (treated as invalid match)", async () => {
    const credential = makeCredential({ ownerSessionId: "session-owner" });
    const result = await refreshOAuthCredentialForRuntime({
      credential,
      requestingSessionId: "",
    });
    expect(result).toBeNull();
  });
});
