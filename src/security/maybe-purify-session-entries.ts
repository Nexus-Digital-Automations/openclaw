/**
 * Owner: security/maybe-purify-session-entries
 *
 * D.3 — shared parse-post-hook helper that bridges parsed
 * Pi SessionEntry arrays into purifyParsedTranscriptEntries.
 *
 * Why shared: three transcript-parsing consumers need identical
 * purification semantics — btw-transcript (shipped D.3 part 1/3),
 * pi-embedded-runner transcript-file-state (D.3 part 2), and the
 * compaction successor builder (D.3 part 3). Co-locating the helper
 * keeps the JSON round-trip / fail-open behavior coherent across
 * consumers; drift would let one consumer skip purification a peer
 * applied.
 *
 * Pi's SessionEntry is owned upstream and varies by entry type. To
 * rewrite the textual content safely in-memory we serialize each
 * entry to JSON, send the serialized line through the purifier, and
 * re-parse the sanitized form. Entries whose post-rewrite shape no
 * longer parses fall back to the original (fail-open per the
 * purifier's defense-in-depth posture).
 *
 * @stable
 */
import type { SessionEntry as PiSessionEntry } from "../agents/sessions/index.js";
import { diagnosticLogger as diag } from "../logging/diagnostic.js";
import { purifyParsedTranscriptEntries } from "./context-purification.js";

export async function maybePurifySessionEntries(
  entries: PiSessionEntry[],
  priorCorrelationId: string | undefined,
  sessionId: string,
): Promise<PiSessionEntry[]> {
  if (!priorCorrelationId || entries.length === 0) {
    return entries;
  }
  const verdict = await purifyParsedTranscriptEntries<PiSessionEntry>({
    entries,
    priorCorrelationId,
    getContent: (entry) => JSON.stringify(entry),
    setContent: (original, sanitized) => {
      try {
        return JSON.parse(sanitized) as PiSessionEntry;
      } catch {
        return original;
      }
    },
  });
  if (!verdict.purified) {
    return entries;
  }
  diag.debug(
    `pi session entries purified: sessionId=${sessionId} corr=${priorCorrelationId} removed=${verdict.removedCount}`,
  );
  return verdict.entries;
}
