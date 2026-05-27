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
  const compiled = compilePatternTable(inputs);
  if (compiled === null) {
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

type CompiledPatterns = {
  root: AcNode;
  longestPatternLength: number;
};

type AcNode = {
  // Sparse goto map. Keyed by UTF-16 code unit; matches behave on a per-code-unit
  // basis, which is what the secret/canary/body sets are stored as anyway.
  next: Map<number, AcNode>;
  fail: AcNode | null;
  outputs: PatternMeta[];
};

type PatternMeta = {
  literal: string;
  family: FirewallFamily;
};

function compilePatternTable(inputs?: Partial<OutputFirewallInputs>): CompiledPatterns | null {
  const patterns = collectPatterns(inputs);
  if (patterns.length === 0) {
    return null;
  }
  const root: AcNode = { next: new Map(), fail: null, outputs: [] };
  let longest = 0;
  for (const pattern of patterns) {
    insertPattern(root, pattern);
    if (pattern.literal.length > longest) {
      longest = pattern.literal.length;
    }
  }
  wireFailureLinks(root);
  return { root, longestPatternLength: longest };
}

function collectPatterns(inputs?: Partial<OutputFirewallInputs>): readonly PatternMeta[] {
  const out: PatternMeta[] = [];
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
  out: PatternMeta[],
  seen: Set<string>,
  source: ReadonlySet<string>,
  family: FirewallFamily,
): void {
  for (const literal of source) {
    if (literal.length < MIN_FIREWALL_PATTERN_LENGTH || seen.has(literal)) {
      continue;
    }
    seen.add(literal);
    out.push({ literal, family });
  }
}

function insertPattern(root: AcNode, pattern: PatternMeta): void {
  let cur = root;
  for (let i = 0; i < pattern.literal.length; i++) {
    const code = pattern.literal.charCodeAt(i);
    let child = cur.next.get(code);
    if (child === undefined) {
      child = { next: new Map(), fail: null, outputs: [] };
      cur.next.set(code, child);
    }
    cur = child;
  }
  cur.outputs.push(pattern);
}

function wireFailureLinks(root: AcNode): void {
  const queue: AcNode[] = [];
  for (const child of root.next.values()) {
    child.fail = root;
    queue.push(child);
  }
  while (queue.length > 0) {
    const node = queue.shift() as AcNode;
    for (const [code, child] of node.next) {
      queue.push(child);
      child.fail = resolveFailureTarget(root, node.fail, code);
      for (const output of child.fail.outputs) {
        child.outputs.push(output);
      }
    }
  }
}

function resolveFailureTarget(root: AcNode, start: AcNode | null, code: number): AcNode {
  let cursor = start;
  while (cursor !== null) {
    const candidate = cursor.next.get(code);
    if (candidate !== undefined) {
      return candidate;
    }
    cursor = cursor.fail;
  }
  return root.next.get(code) ?? root;
}

function automatonFirewall(compiled: CompiledPatterns): OutputFirewall {
  // Cross-chunk matches are honoured by carrying the AC frontier node forward
  // across `scan()` calls. No textual carry buffer is needed: the automaton
  // is byte-driven and already remembers the longest partial match prefix.
  const state = { node: compiled.root };
  return {
    scan(chunk) {
      if (chunk.length === 0) {
        return null;
      }
      const step = stepAutomaton(compiled, state.node, chunk);
      state.node = step.endNode;
      if (step.match === null) {
        return null;
      }
      // `endIndex` is exclusive within `chunk`. If the pattern straddled
      // earlier chunks, `startInChunk` is negative; clamp to 0 so the offset
      // means "first matched byte in this chunk, or chunk start if earlier".
      const startInChunk = step.match.endIndex - step.match.pattern.literal.length;
      return {
        family: step.match.pattern.family,
        literal: step.match.pattern.literal,
        offset: Math.max(0, startInChunk),
      };
    },
    reset() {
      state.node = compiled.root;
    },
  };
}

type AutomatonMatch = {
  pattern: PatternMeta;
  endIndex: number;
};

type AutomatonStep = {
  endNode: AcNode;
  match: AutomatonMatch | null;
};

function stepAutomaton(compiled: CompiledPatterns, start: AcNode, chunk: string): AutomatonStep {
  let node = start;
  for (let i = 0; i < chunk.length; i++) {
    node = advance(compiled.root, node, chunk.charCodeAt(i));
    if (node.outputs.length > 0) {
      return { endNode: node, match: { pattern: node.outputs[0], endIndex: i + 1 } };
    }
  }
  return { endNode: node, match: null };
}

function advance(root: AcNode, from: AcNode, code: number): AcNode {
  let cursor: AcNode | null = from;
  while (cursor !== null) {
    const next = cursor.next.get(code);
    if (next !== undefined) {
      return next;
    }
    cursor = cursor.fail;
  }
  return root;
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
