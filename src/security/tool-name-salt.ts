/**
 * Owner: security/tool-name-salt.
 *
 * A.2 — schema fuzzing primitive. Per-turn deterministic salt that rotates
 * the on-the-wire tool name the model sees, while leaving the tool's
 * JSON schema byte-identical. An adversarial prompt that hardcodes a
 * specific tool name (e.g. "call fs_write with these args") cannot
 * resolve once the on-the-wire name has rotated. The reverse map strips
 * the suffix at dispatch.
 *
 * Invariants:
 *  - Deterministic: `computeTurnSalt(sessionId, turnCounter)` is a pure
 *    function. Provider conversion (forward map) and gateway dispatch
 *    (reverse map) compute the same salt independently; no shared
 *    registry, no in-flight handshake.
 *  - Stable within a turn: every tool name emitted in turn N for session S
 *    carries the same salt. Two consecutive provider calls in one turn
 *    produce identical on-the-wire names, so prompt-cache identity is
 *    preserved within a turn.
 *  - Distinct across turns: turn N+1 uses a different salt than turn N
 *    (proven by the SHA-256 avalanche over the counter delta).
 *  - Names only, never schemas: the JSON-schema bytes the model sees stay
 *    byte-identical. Provider tool-grammar caching keyed on schema shape
 *    is preserved.
 *  - Reversible: `parseToolNameSalt(salted, salt)` returns the original
 *    name iff the suffix matches; otherwise returns `null`. Callers
 *    branch on `null` and surface a structured dispatch refusal rather
 *    than silently looking up the unsalted name (that would defeat the
 *    defense).
 *
 * Non-goals (deferred to a follow-up commit):
 *  - Live integration into anthropic/openai/google transport conversion.
 *  - Per-session turn counter store: each transport will call
 *    `incrementSessionTurnCounter(sessionId)` at turn entry.
 *  - Reverse-map enforcement at tools-invoke-shared.ts dispatch.
 *
 * @stable
 */
import { createHash } from "node:crypto";

const SALT_LENGTH = 8;
const SALT_DELIMITER = "__cz_";
// WHY: 8 hex chars (32 bits) over a SHA-256 truncation is enough entropy
// to defeat hardcoded-name injection while keeping the on-the-wire token
// short. Collisions inside a 256-tool registry are vanishingly rare and
// would manifest as a dispatch refusal (safe fail), not silent misroute.
const SALT_HEX_CHARS = SALT_LENGTH;

/**
 * Compute the per-turn salt that should be appended to every tool name
 * emitted to the model. Pure function of (sessionId, turnCounter); no IO.
 *
 * Failure modes:
 *  - throws if `sessionId` is empty or not a string
 *  - throws if `turnCounter` is not a non-negative integer
 */
export function computeTurnSalt(sessionId: string, turnCounter: number): string {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    throw new Error("computeTurnSalt: sessionId must be a non-empty string");
  }
  if (!Number.isInteger(turnCounter) || turnCounter < 0) {
    throw new Error("computeTurnSalt: turnCounter must be a non-negative integer");
  }
  const digest = createHash("sha256")
    .update(`tool-name-salt:${sessionId}:${turnCounter}`, "utf8")
    .digest("hex");
  return digest.slice(0, SALT_HEX_CHARS);
}

/**
 * Apply a salt to an original tool name. The salt rides in a fixed suffix
 * so the reverse map is unambiguous even for tool names containing
 * underscores.
 *
 * Failure modes:
 *  - throws if `original` is empty or already contains the delimiter
 *    (which would make the reverse map ambiguous)
 *  - throws if `salt` is not the expected 8-hex-char shape
 */
export function applyToolNameSalt(original: string, salt: string): string {
  if (typeof original !== "string" || original.length === 0) {
    throw new Error("applyToolNameSalt: original must be a non-empty string");
  }
  if (original.includes(SALT_DELIMITER)) {
    throw new Error(
      `applyToolNameSalt: original tool name must not contain reserved delimiter "${SALT_DELIMITER}"`,
    );
  }
  if (!isValidSalt(salt)) {
    throw new Error(`applyToolNameSalt: salt must be exactly ${SALT_HEX_CHARS} hex chars`);
  }
  return `${original}${SALT_DELIMITER}${salt}`;
}

/**
 * Reverse a salted tool name. Returns the original name iff the suffix
 * matches the expected salt; returns `null` on any mismatch. Callers
 * MUST surface a structured dispatch refusal on `null` rather than fall
 * back to an unsalted lookup — the silent fallback would defeat the
 * defense.
 */
export function parseToolNameSalt(saltedName: string, expectedSalt: string): string | null {
  if (typeof saltedName !== "string" || saltedName.length === 0) {
    return null;
  }
  if (!isValidSalt(expectedSalt)) {
    return null;
  }
  const suffix = `${SALT_DELIMITER}${expectedSalt}`;
  if (!saltedName.endsWith(suffix)) {
    return null;
  }
  const original = saltedName.slice(0, saltedName.length - suffix.length);
  if (original.length === 0) {
    return null;
  }
  return original;
}

function isValidSalt(salt: string): boolean {
  return typeof salt === "string" && salt.length === SALT_HEX_CHARS && /^[0-9a-f]+$/.test(salt);
}

// Per-session turn counter. Module-local map keyed by sessionId. The
// counter starts at 0 on first read; `incrementSessionTurnCounter` returns
// the value AFTER the increment, so callers should call it once per
// turn-entry and use the returned value for the salt. Reset is only used
// by tests.
const sessionTurnCounters = new Map<string, number>();

/**
 * Advance the per-session turn counter by one and return the new value.
 * Call once per turn-entry at the transport boundary.
 *
 * @internal — paired with `currentSessionTurnCounter` for symmetry.
 */
export function incrementSessionTurnCounter(sessionId: string): number {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    throw new Error("incrementSessionTurnCounter: sessionId must be a non-empty string");
  }
  const next = (sessionTurnCounters.get(sessionId) ?? 0) + 1;
  sessionTurnCounters.set(sessionId, next);
  return next;
}

/**
 * Read the current per-session turn counter without advancing. Returns 0
 * for unknown sessions.
 *
 * @internal — for dispatch-side salt computation between transports.
 */
export function currentSessionTurnCounter(sessionId: string): number {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    return 0;
  }
  return sessionTurnCounters.get(sessionId) ?? 0;
}

/**
 * Reset the per-session turn counter map. Tests only.
 *
 * @internal
 */
export function clearSessionTurnCountersForTests(): void {
  sessionTurnCounters.clear();
}
