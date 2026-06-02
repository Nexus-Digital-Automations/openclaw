// Owner: agents/output-firewall. Pure scanner that streaming transport
// adapters call on every model-output chunk. Matches against the canonical
// process registries (secret literals + external-content bodies) so any byte
// string the gateway already knows is sensitive cannot leave the gateway via
// the assistant text channel.
//
// Design choice: literal scan, not regex / Aho-Corasick. The total pattern
// count in single-operator deployments is small (10s of secrets, dozens of
// external bodies); JS `String.includes` is cheap enough and avoids the
// per-chunk regex rebuild cost. A trailing carryover keeps cross-chunk
// matches honest without buffering the entire stream.

import { snapshotExternalContentBodies } from "../shared/process-external-content-bodies.js";
import { snapshotResolvedSecrets } from "../shared/process-secret-literals.js";

const MIN_FIREWALL_LITERAL_LENGTH = 8;

export type OutputFirewallState = {
  /** Tail of the previous chunk, kept so cross-chunk matches do not slip through. */
  carry: string;
};

export type OutputFirewallVerdict =
  | { kind: "pass"; sanitized: string; nextState: OutputFirewallState }
  | { kind: "block"; matched: string; sanitized: string; nextState: OutputFirewallState };

/**
 * Build an empty firewall state. Use once per stream lifetime.
 *
 * @stable
 */
export function createOutputFirewallState(): OutputFirewallState {
  return { carry: "" };
}

/**
 * Scan one output chunk against the canonical literal registries.
 *
 * Failure mode: when a tainted literal is found anywhere in the
 * carry+chunk window, returns `kind: "block"` with the matched literal
 * and a redacted `sanitized` body. Callers must drop the unredacted
 * source bytes and propagate the block decision upstream.
 *
 * @stable
 */
export function scanOutputChunk(chunk: string, state: OutputFirewallState): OutputFirewallVerdict {
  const literals = collectLiterals();
  if (literals.length === 0 || chunk.length === 0) {
    return { kind: "pass", sanitized: chunk, nextState: nextStateFor(chunk, 0) };
  }
  const longestLiteral = literals.reduce((max, lit) => Math.max(max, lit.length), 0);
  const window = `${state.carry}${chunk}`;
  for (const literal of literals) {
    if (!window.includes(literal)) {
      continue;
    }
    return {
      kind: "block",
      matched: literal,
      sanitized: chunk.split(literal).join("«REDACTED»"),
      nextState: nextStateFor(window, longestLiteral),
    };
  }
  return { kind: "pass", sanitized: chunk, nextState: nextStateFor(window, longestLiteral) };
}

function collectLiterals(): readonly string[] {
  const merged: string[] = [];
  for (const value of snapshotResolvedSecrets()) {
    if (value.length >= MIN_FIREWALL_LITERAL_LENGTH) {
      merged.push(value);
    }
  }
  for (const value of snapshotExternalContentBodies()) {
    if (value.length >= MIN_FIREWALL_LITERAL_LENGTH) {
      merged.push(value);
    }
  }
  return merged;
}

function nextStateFor(window: string, longestLiteral: number): OutputFirewallState {
  if (longestLiteral <= 1 || window.length <= longestLiteral) {
    return { carry: window };
  }
  return { carry: window.slice(window.length - (longestLiteral - 1)) };
}
