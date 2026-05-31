/**
 * Owner: security/session-secret-isolation.
 *
 * G.3 — lift single-tenant assumption (1/2). Adds a per-session secret
 * registry alongside the existing process-wide `process-secret-literals`
 * registry. The existing one stays the source of truth for operator-owned
 * secrets that should mask in every session; this module covers
 * session-scoped credential resolution that MUST NOT cross session
 * boundaries.
 *
 * Threat model: today every resolved secret is process-global, which is
 * fine for single-operator deployments but unsafe the moment two
 * adversarial sessions share one gateway. With this registry, session A's
 * resolved bytes are unreadable from session B even with the same plugin
 * code path — `snapshotSessionSecrets(b)` returns A's set scoped to B
 * (i.e. only B's own secrets), and `refuseCrossSessionRead(a, b)` throws
 * a typed error so callers cannot silently fall back to the process
 * registry.
 *
 * @stable
 */

const sessionSecretLiterals = new Map<string, Set<string>>();

/**
 * Cross-session read attempted. Callers must surface this as a structured
 * security event rather than catching and falling back to the process
 * registry — silent fallback would defeat the isolation.
 *
 * @stable
 */
export class CrossSessionSecretReadError extends Error {
  readonly ownerSessionId: string;
  readonly requesterSessionId: string;

  constructor(ownerSessionId: string, requesterSessionId: string) {
    super(
      `Cross-session secret read refused: owner=${ownerSessionId} requester=${requesterSessionId}`,
    );
    this.name = "CrossSessionSecretReadError";
    this.ownerSessionId = ownerSessionId;
    this.requesterSessionId = requesterSessionId;
  }
}

/**
 * Record a resolved secret byte string scoped to a single session. Empty
 * sessionId or empty value is dropped silently — same shape as the
 * process registry's defensive floor.
 *
 * @stable
 */
export function recordSessionSecret(sessionId: string, value: string): void {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    return;
  }
  if (typeof value !== "string" || value.length === 0) {
    return;
  }
  let bucket = sessionSecretLiterals.get(sessionId);
  if (!bucket) {
    bucket = new Set<string>();
    sessionSecretLiterals.set(sessionId, bucket);
  }
  bucket.add(value);
}

/**
 * Snapshot the secrets owned by a single session. Returns an empty array
 * for unknown sessions. Use for building a per-session firewall input.
 *
 * @stable
 */
export function snapshotSessionSecrets(sessionId: string): readonly string[] {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    return [];
  }
  const bucket = sessionSecretLiterals.get(sessionId);
  return bucket ? [...bucket] : [];
}

/**
 * Assert that a requester session is reading its own bucket. Throws
 * `CrossSessionSecretReadError` on mismatch so callers cannot silently
 * fall back.
 *
 * Both arguments must be non-empty strings; an empty value is treated as
 * a mismatch.
 *
 * @stable
 */
export function refuseCrossSessionRead(ownerSessionId: string, requesterSessionId: string): void {
  if (typeof ownerSessionId !== "string" || ownerSessionId.length === 0) {
    throw new CrossSessionSecretReadError(ownerSessionId, requesterSessionId);
  }
  if (typeof requesterSessionId !== "string" || requesterSessionId.length === 0) {
    throw new CrossSessionSecretReadError(ownerSessionId, requesterSessionId);
  }
  if (ownerSessionId !== requesterSessionId) {
    throw new CrossSessionSecretReadError(ownerSessionId, requesterSessionId);
  }
}

/**
 * Evict a single ended session's bucket. Unlike the process-wide registry
 * (whose literals intentionally live for the process lifetime), a session's
 * resolved secrets must not outlive the session — that is the point of
 * residency reduction. Call this from session-end teardown once the session
 * can no longer produce output that would need redaction.
 *
 * Returns the number of literals evicted (0 for an unknown session) so the
 * caller can emit an accurate telemetry count. No-ops on an empty sessionId.
 *
 * @stable
 */
export function clearSessionSecrets(sessionId: string): number {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    return 0;
  }
  const bucket = sessionSecretLiterals.get(sessionId);
  if (!bucket) {
    return 0;
  }
  const evicted = bucket.size;
  sessionSecretLiterals.delete(sessionId);
  return evicted;
}

/**
 * Wipe every session's bucket. Tests only — production callers must use
 * `clearSessionSecrets(sessionId)` for a specific ended session instead.
 *
 * @internal
 */
export function clearSessionSecretsForTests(): void {
  sessionSecretLiterals.clear();
}
