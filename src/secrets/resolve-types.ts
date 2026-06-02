export type SecretRefResolveCache = {
  resolvedByRefKey?: Map<string, Promise<unknown>>;
  filePayloadByProvider?: Map<string, Promise<unknown>>;
  // Populated by resolveSecretRefValues with every successfully-resolved string
  // value, so redactors can mask exact bytes the system itself decrypted —
  // closing the gap left by regex-only patterns in `src/logging/redact.ts`.
  // Caller-owned: the same Set lives for the duration of the request/session
  // that owns this cache.
  resolvedValues?: Set<string>;
};
