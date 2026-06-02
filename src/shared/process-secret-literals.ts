// Owner: shared. Single source of truth for "the bytes the gateway just
// decrypted in this process." Lives in shared/ so logging (consumer) and
// secrets (producer) can both reach it without taking a dep on each other.
//
// Per AGENTS.md the gateway is single-operator/single-tenant: a process-wide
// registry is acceptable because there is no second principal whose unrelated
// text could be coincidence-redacted across session boundaries.
//
// State: a single Set<string>. No cache eviction — once a literal is known
// secret it stays masked for the life of the process; restart wipes it.

const resolvedSecretLiterals = new Set<string>();

/**
 * Record a decrypted secret byte string so downstream sinks mask it on sight.
 *
 * Values shorter than 4 chars are dropped at the redactor compile step rather
 * than here so that callers cannot accidentally bypass the floor by writing a
 * different filter. Empty strings are ignored.
 *
 * @stable
 */
export function recordResolvedSecret(value: string): void {
  if (typeof value !== "string" || value.length === 0) {
    return;
  }
  resolvedSecretLiterals.add(value);
}

/**
 * Snapshot the current literal set for the redactor. Returns a readonly array
 * so the caller cannot mutate the underlying registry.
 *
 * @stable
 */
export function snapshotResolvedSecrets(): readonly string[] {
  return [...resolvedSecretLiterals];
}

/**
 * Reset for tests. Production callers must not use this — a stale literal
 * staying in the registry is strictly safer than dropping one early.
 *
 * @internal
 */
export function clearResolvedSecretsForTests(): void {
  resolvedSecretLiterals.clear();
}
