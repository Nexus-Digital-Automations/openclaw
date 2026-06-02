import { normalizeSecretInput } from "../../utils/normalize-secret-input.js";
import { ensureAuthStoreFile, resolveAuthStorePath } from "./paths.js";
import { updateAuthProfileStoreWithLock } from "./store.js";
import type { AuthProfileCredential, AuthProfileStore } from "./types.js";

function normalizeAuthProfileCredential(credential: AuthProfileCredential): AuthProfileCredential {
  if (credential.type === "api_key") {
    if (typeof credential.key !== "string") {
      return credential;
    }
    const { key: _key, ...rest } = credential;
    const key = normalizeSecretInput(credential.key);
    return {
      ...rest,
      ...(key ? { key } : {}),
    };
  }
  if (credential.type === "token") {
    if (typeof credential.token !== "string") {
      return credential;
    }
    const { token: _token, ...rest } = credential;
    const token = normalizeSecretInput(credential.token);
    return { ...rest, ...(token ? { token } : {}) };
  }
  return credential;
}

// G.3 — stamp ownerSessionId onto an OAuth credential when sessionId is set
// AND the credential does not yet carry one. Existing stamps are preserved
// (matches the refresh-merge preservation contract in oauth.ts so the original
// owning session is never silently rewritten by a later upsert).
function stampOwnerSessionIfMissing(
  credential: AuthProfileCredential,
  sessionId: string | undefined,
): AuthProfileCredential {
  if (!sessionId) {
    return credential;
  }
  if (credential.type !== "oauth") {
    return credential;
  }
  if (credential.ownerSessionId) {
    return credential;
  }
  return { ...credential, ownerSessionId: sessionId };
}

export async function upsertAuthProfileWithLock(params: {
  profileId: string;
  credential: AuthProfileCredential;
  agentDir?: string;
  // G.3 — when set, stamps ownerSessionId on a freshly-constructed OAuth
  // credential so future cross-session refresh attempts can be refused.
  // Bootstrap callers (CLI migrate, external-cli sync) pass undefined per
  // grandfather policy; login / onboarding wizards thread the active session.
  sessionId?: string;
}): Promise<AuthProfileStore | null> {
  const authPath = resolveAuthStorePath(params.agentDir);
  ensureAuthStoreFile(authPath);

  try {
    const credential = stampOwnerSessionIfMissing(
      normalizeAuthProfileCredential(params.credential),
      params.sessionId,
    );
    return await updateAuthProfileStoreWithLock({
      agentDir: params.agentDir,
      saveOptions: {
        filterExternalAuthProfiles: false,
        syncExternalCli: false,
      },
      updater: (store) => {
        store.profiles[params.profileId] = credential;
        return true;
      },
    });
  } catch {
    return null;
  }
}
