// Owner: shared. Mirrors process-secret-literals: a single Set<string> of
// every external-content body the gateway has wrapped this process. Lives in
// shared/ so security (producer) and agents (consumer at exec-approval time)
// can both reach it without coupling those layers.
//
// Per AGENTS.md single-tenant threat model, process-wide scope is acceptable.
// A 16-char floor keeps short common substrings ("Hello world!") from forcing
// approval on every tool call.
//
// State: a single Set<string>. No eviction — once a body is tainted it stays
// tainted for the life of the process; restart wipes it.

const MIN_TAINT_LENGTH = 16;

const externalContentBodies = new Set<string>();

/**
 * Record an external-content body. Strings shorter than MIN_TAINT_LENGTH are
 * dropped so common phrases do not force approval on every benign tool call.
 *
 * @stable
 */
export function recordExternalContentBody(body: string): void {
  if (typeof body !== "string" || body.length < MIN_TAINT_LENGTH) {
    return;
  }
  externalContentBodies.add(body);
}

/**
 * Snapshot the current taint set. Returns a readonly array so the caller
 * cannot mutate the underlying registry.
 *
 * @stable
 */
export function snapshotExternalContentBodies(): readonly string[] {
  return [...externalContentBodies];
}

/**
 * Return the first recorded body that appears as a substring of any element of
 * `argv`, or undefined if none do. Used by the exec-approval gate to detect
 * tool calls whose arguments embed model-pasted external content.
 *
 * @stable
 */
export function findArgvExternalContentTaint(argv: readonly string[]): string | undefined {
  if (argv.length === 0 || externalContentBodies.size === 0) {
    return undefined;
  }
  for (const arg of argv) {
    if (typeof arg !== "string" || arg.length < MIN_TAINT_LENGTH) {
      continue;
    }
    for (const body of externalContentBodies) {
      if (arg.includes(body)) {
        return body;
      }
    }
  }
  return undefined;
}

/**
 * Reset for tests. Production callers must not use this.
 *
 * @internal
 */
export function clearExternalContentBodiesForTests(): void {
  externalContentBodies.clear();
}
