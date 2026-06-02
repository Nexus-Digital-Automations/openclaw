/**
 * Owner: security/tool-output-redactor.
 *
 * Inbound symmetric counterpart to `output-firewall.ts` (P0.1). Where the
 * firewall scans the model's outbound text stream for echoes of sensitive
 * bytes, this redactor scans the *inbound* tool-execution payload (stdout,
 * stderr, structured result fields) BEFORE the gateway feeds it back into
 * the model context. Any registered literal — resolved session secrets,
 * per-wrap external-content canaries, wrapped external-content marker
 * bodies — is replaced in-place with a family-tagged placeholder so the
 * model never sees the raw bytes.
 *
 * Invariants:
 * - One redactor instance per assistant turn. Build the pattern table once
 *   from the live registry snapshots and reuse across every tool result
 *   produced in that turn. Snapshots are not refreshed mid-instance; a new
 *   turn means a new redactor.
 * - Patterns shorter than `MIN_REDACTOR_PATTERN_LENGTH` are dropped at
 *   compile time. Common short substrings would otherwise corrupt benign
 *   tool output (e.g. masking the literal `null` or `true`).
 * - Field names are never rewritten. Only string VALUES are scanned, and
 *   only inside the recursive walk over arrays and plain objects.
 * - Family tags: `<redacted:secret>`, `<redacted:canary>`,
 *   `<redacted:external-content>`. The "marker" family from the firewall
 *   maps to the user-facing label `external-content` because that is what
 *   downstream operators expect when reading masked tool output.
 * - Pure: snapshotting the registries happens at construction; the
 *   returned `redact()` does no I/O and never throws into the caller.
 *
 * Failure mode: if the pattern table cannot be built, `redact()` is a
 * structural deep-clone passthrough. The caller (tools-invoke) is
 * expected to wrap the call in its own try/catch and log
 * `tool_output_redactor.error` on any unexpected throw so a redactor
 * crash never blocks a tool result from returning to the model — symmetric
 * to the audit-write best-effort posture in P0.6.
 */

import { snapshotResolvedSecrets } from "../shared/process-secret-literals.js";
import { type CompiledAC, compileAc, stepAc } from "./aho-corasick.js";
import {
  snapshotExternalContentCanaries,
  snapshotExternalContentMarkerBodies,
} from "./external-content.js";

const MIN_REDACTOR_PATTERN_LENGTH = 8;

export type RedactorFamily = "secret" | "canary" | "marker";

const FAMILY_REPLACEMENT: Readonly<Record<RedactorFamily, string>> = {
  secret: "<redacted:secret>",
  canary: "<redacted:canary>",
  marker: "<redacted:external-content>",
};

export type ToolOutputPayload = unknown;

export type ToolOutputRedactor = {
  redact(payload: ToolOutputPayload): ToolOutputPayload;
};

export type ToolOutputRedactorInputs = {
  secrets: ReadonlySet<string>;
  canaries: ReadonlySet<string>;
  markerBodies: ReadonlySet<string>;
};

/**
 * Build a per-turn tool-output redactor from the live taint registries.
 * Callers may inject explicit pattern sets for tests; otherwise the live
 * process snapshots are used.
 *
 * @stable
 */
export function createToolOutputRedactor(
  inputs?: Partial<ToolOutputRedactorInputs>,
): ToolOutputRedactor {
  const entries = collectEntries(inputs);
  const compiled = compileAc<RedactorFamily>(entries, MIN_REDACTOR_PATTERN_LENGTH);
  if (compiled.patternCount === 0) {
    return { redact: (payload) => payload };
  }
  return {
    redact(payload) {
      return walkValue(payload, compiled);
    },
  };
}

function collectEntries(
  inputs?: Partial<ToolOutputRedactorInputs>,
): ReadonlyArray<{ literal: string; family: RedactorFamily }> {
  const out: Array<{ literal: string; family: RedactorFamily }> = [];
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
  out: Array<{ literal: string; family: RedactorFamily }>,
  seen: Set<string>,
  source: ReadonlySet<string>,
  family: RedactorFamily,
): void {
  for (const literal of source) {
    if (seen.has(literal)) {
      continue;
    }
    seen.add(literal);
    out.push({ literal, family });
  }
}

type AcMatch = {
  start: number;
  end: number;
  family: RedactorFamily;
};

function scanAllMatches(compiled: CompiledAC<RedactorFamily>, text: string): readonly AcMatch[] {
  const matches: AcMatch[] = [];
  let node = compiled.root;
  for (let i = 0; i < text.length; i++) {
    const stepped = stepAc(compiled, node, text.charCodeAt(i));
    node = stepped.node;
    for (const output of stepped.matches) {
      matches.push({
        start: i + 1 - output.literal.length,
        end: i + 1,
        family: output.family,
      });
    }
  }
  return matches;
}

function redactString(text: string, compiled: CompiledAC<RedactorFamily>): string {
  if (text.length === 0) {
    return text;
  }
  const matches = scanAllMatches(compiled, text);
  if (matches.length === 0) {
    return text;
  }
  const chosen = chooseNonOverlappingMatches(matches);
  if (chosen.length === 0) {
    return text;
  }
  let out = "";
  let cursor = 0;
  for (const match of chosen) {
    if (match.start > cursor) {
      out += text.slice(cursor, match.start);
    }
    out += FAMILY_REPLACEMENT[match.family];
    cursor = match.end;
  }
  if (cursor < text.length) {
    out += text.slice(cursor);
  }
  return out;
}

function chooseNonOverlappingMatches(matches: readonly AcMatch[]): readonly AcMatch[] {
  // Earliest-start wins; on tie, prefer the longest literal so a containing
  // pattern is masked over a contained one.
  const sorted = [...matches].sort((a, b) => {
    if (a.start !== b.start) {
      return a.start - b.start;
    }
    return b.end - a.end;
  });
  const out: AcMatch[] = [];
  let lastEnd = -1;
  for (const match of sorted) {
    if (match.start >= lastEnd) {
      out.push(match);
      lastEnd = match.end;
    }
  }
  return out;
}

function walkValue(value: unknown, compiled: CompiledAC<RedactorFamily>): unknown {
  if (typeof value === "string") {
    return redactString(value, compiled);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => walkValue(entry, compiled));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = walkValue(entry, compiled);
    }
    return out;
  }
  return value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}
