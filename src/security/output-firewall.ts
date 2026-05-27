/**
 * Owner: security/output-firewall.
 *
 * Streaming Aho-Corasick scanner that watches every model-output text chunk
 * for echoes of bytes the gateway has already classified as sensitive:
 * resolved session secrets, per-wrap external-content canaries, and wrapped
 * external-content marker bodies.
 *
 * Invariants:
 * - One firewall instance per assistant turn. State (Aho-Corasick frontier
 *   node + carryover buffer) is per-instance and not thread-safe; do not
 *   share across turns or across the request boundary.
 * - Patterns shorter than `MIN_FIREWALL_PATTERN_LENGTH` are dropped at compile
 *   time. Common short substrings would otherwise trip on benign output.
 * - `scan()` returns `null` for clean chunks. `null` is a domain-correct
 *   "no trip" verdict, not an error sentinel. The first trip per turn is
 *   reported; the firewall does not aggregate multiple trips.
 * - The matched literal is the exposed `literal` field. Callers MUST treat
 *   it as sensitive and never log it as plain text — that's the bytes we
 *   are trying to keep from leaving the gateway.
 *
 * State diagram (per instance):
 *
 *   created ──scan(chunk)──▶ scanning ──trip──▶ tripped
 *      │                        │                 │
 *      └────────reset()─────────┴─────────────────┘
 *
 * Tripped instances continue to return trips on further `scan()` calls; the
 * wire layer should stop forwarding deltas once it sees the first trip.
 */

import { snapshotResolvedSecrets } from "../shared/process-secret-literals.js";
import { type CompiledAC, compileAc, stepAc } from "./aho-corasick.js";
import {
  snapshotExternalContentCanaries,
  snapshotExternalContentMarkerBodies,
} from "./external-content.js";

const MIN_FIREWALL_PATTERN_LENGTH = 8;

export type FirewallFamily = "secret" | "canary" | "marker";

export type FirewallTrip = {
  family: FirewallFamily;
  literal: string;
  offset: number;
};

export type OutputFirewall = {
  scan(chunk: string): FirewallTrip | null;
  reset(): void;
};

export type OutputFirewallInputs = {
  secrets: ReadonlySet<string>;
  canaries: ReadonlySet<string>;
  markerBodies: ReadonlySet<string>;
};

/**
 * Build a per-turn output firewall from the canonical taint registries.
 * Caller may inject explicit pattern sets (tests, alternate registries);
 * otherwise the live process snapshots are used.
 *
 * Failure mode: returns an inert firewall (every `scan` returns `null`) if
 * every input set, after the min-length filter, is empty. This keeps hot
 * paths cheap when no secrets are resolved yet.
 *
 * @stable
 */
export function createOutputFirewall(inputs?: Partial<OutputFirewallInputs>): OutputFirewall {
  const entries = collectEntries(inputs);
  const compiled = compileAc<FirewallFamily>(entries, MIN_FIREWALL_PATTERN_LENGTH);
  if (compiled.patternCount === 0) {
    return inertFirewall();
  }
  return automatonFirewall(compiled);
}

/**
 * Snapshot the live process taint registries. Convenience wrapper so the
 * wire layer can call `createOutputFirewall(snapshotFirewallInputs())`.
 *
 * @stable
 */
export function snapshotFirewallInputs(): OutputFirewallInputs {
  return {
    secrets: new Set(snapshotResolvedSecrets()),
    canaries: new Set(snapshotExternalContentCanaries()),
    markerBodies: new Set(snapshotExternalContentMarkerBodies()),
  };
}

function collectEntries(
  inputs?: Partial<OutputFirewallInputs>,
): ReadonlyArray<{ literal: string; family: FirewallFamily }> {
  const out: Array<{ literal: string; family: FirewallFamily }> = [];
  const seen = new Set<string>();
  const secrets = inputs?.secrets ?? new Set(snapshotResolvedSecrets());
  const canaries = inputs?.canaries ?? new Set(snapshotExternalContentCanaries());
  const markerBodies = inputs?.markerBodies ?? new Set(snapshotExternalContentMarkerBodies());
  pushFamily(out, seen, secrets, "secret");
  pushFamily(out, seen, canaries, "canary");
  pushFamily(out, seen, markerBodies, "marker");
  return out;
}

function pushFamily(
  out: Array<{ literal: string; family: FirewallFamily }>,
  seen: Set<string>,
  source: ReadonlySet<string>,
  family: FirewallFamily,
): void {
  for (const literal of source) {
    if (seen.has(literal)) {
      continue;
    }
    seen.add(literal);
    out.push({ literal, family });
  }
}

function automatonFirewall(compiled: CompiledAC<FirewallFamily>): OutputFirewall {
  // Cross-chunk matches are honoured by carrying the AC frontier node forward
  // across `scan()` calls. No textual carry buffer is needed: the automaton
  // is byte-driven and already remembers the longest partial match prefix.
  const state = { node: compiled.root };
  return {
    scan(chunk) {
      if (chunk.length === 0) {
        return null;
      }
      let firstMatch: { literal: string; family: FirewallFamily; endIndex: number } | null = null;
      for (let i = 0; i < chunk.length; i++) {
        const stepped = stepAc(compiled, state.node, chunk.charCodeAt(i));
        state.node = stepped.node;
        if (firstMatch === null && stepped.matches.length > 0) {
          const m = stepped.matches[0];
          firstMatch = { literal: m.literal, family: m.family, endIndex: i + 1 };
          break;
        }
      }
      if (firstMatch === null) {
        return null;
      }
      // If the pattern straddled earlier chunks, startInChunk is negative;
      // clamp to 0 so the offset means "first matched byte in this chunk, or
      // chunk start if the pattern began in a prior chunk".
      const startInChunk = firstMatch.endIndex - firstMatch.literal.length;
      return {
        family: firstMatch.family,
        literal: firstMatch.literal,
        offset: Math.max(0, startInChunk),
      };
    },
    reset() {
      state.node = compiled.root;
    },
  };
}

function inertFirewall(): OutputFirewall {
  return {
    scan() {
      return null;
    },
    reset() {
      // No state to clear.
    },
  };
}
