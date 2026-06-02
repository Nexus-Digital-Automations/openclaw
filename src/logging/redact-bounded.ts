const REDACT_REGEX_CHUNK_THRESHOLD = 32_768;
const REDACT_REGEX_CHUNK_SIZE = 16_384;

type BoundedRedactOptions = {
  chunkThreshold?: number;
  chunkSize?: number;
};

// A pattern whose matches can span newlines (the `s`/dotAll flag, or an explicit
// any-character class like `[\s\S]`) can produce an arbitrarily long match — a
// PEM private-key block is the canonical case. Such a match can exceed the scan
// window entirely, and `window.matchAll` never completes it inside any single
// window, so chunking would drop the whole secret unredacted. These patterns are
// anchored-literal / lazy by construction (built-in PEM) and user-supplied ones
// pass safe-regex validation, so running them against the full string is safe.
function matchesCanSpanWindows(pattern: RegExp): boolean {
  if (pattern.dotAll) {
    return true;
  }
  const src = pattern.source;
  return src.includes("[\\s\\S]") || src.includes("[\\S\\s]") || src.includes("[^]");
}

/**
 * Apply `pattern.replace(replacer)` while keeping each regex run's input bounded
 * (the perf/DoS guard from `perf(security): bound regex input`), without the
 * chunk-boundary secret leak that fixed, non-overlapping slices cause.
 *
 * Naive chunking slices the text every `chunkSize` chars and replaces each slice
 * in isolation, so a secret straddling a boundary matches in neither slice and
 * survives unredacted. Instead we scan overlapping windows: advance by
 * `chunkSize` but read an extra `chunkSize` of lookahead, so any match up to
 * `chunkSize` long is seen whole by exactly one window — the one whose primary
 * `[base, base+chunkSize)` region contains the match start. Spans are applied to
 * the original string once, so overlap never double-emits and indices never
 * drift.
 *
 * Two cases would otherwise leave an oversized match unredacted, so both are
 * handled: (1) newline-spanning patterns (PEM, dotAll) can exceed the window and
 * never complete inside one — they run unbounded; (2) a single-line match that
 * reaches a truncated window edge is re-resolved anchored against the full text
 * so it is never clipped.
 *
 * @stable
 */
export function replacePatternBounded(
  text: string,
  pattern: RegExp,
  replacer: Parameters<string["replace"]>[1],
  options?: BoundedRedactOptions,
): string {
  const chunkThreshold = options?.chunkThreshold ?? REDACT_REGEX_CHUNK_THRESHOLD;
  const chunkSize = options?.chunkSize ?? REDACT_REGEX_CHUNK_SIZE;
  if (chunkThreshold <= 0 || chunkSize <= 0 || text.length <= chunkThreshold) {
    return text.replace(pattern, replacer);
  }
  if (!pattern.global || matchesCanSpanWindows(pattern)) {
    // Non-global: `.replace` only touches the first match, so chunking cannot
    // help. Spanning patterns: a match may be longer than any window, so
    // bounding would drop it entirely — scan the whole string.
    return text.replace(pattern, replacer);
  }

  // Non-global, non-sticky clone used to render each owned match in isolation.
  // A single match string replaced by a first-match regex yields identical group
  // args to the caller without depending on any shared `lastIndex` state.
  const single = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ""));
  // Sticky clone that re-resolves a match the window truncated at its right edge
  // by matching anchored at its start against the full text (bounded by the
  // match length, so a long single-line secret is completed, not clipped).
  const anchored = new RegExp(pattern.source, `${single.flags}y`);
  let output = "";
  let cursor = 0; // next un-emitted index in `text`
  for (let base = 0; base < text.length; base += chunkSize) {
    const windowEnd = Math.min(base + chunkSize * 2, text.length);
    const window = text.slice(base, windowEnd);
    const primaryEnd = base + chunkSize;
    const isLastWindow = windowEnd >= text.length;
    for (const match of window.matchAll(pattern)) {
      let matchText = match[0];
      if (matchText.length === 0) {
        continue;
      }
      const absStart = base + (match.index ?? 0);
      // A match starting in the overlap tail belongs to the next window's primary
      // region; defer it so overlapping windows never emit the same span twice.
      // The final window has no successor, so it owns everything to the end.
      if (absStart >= primaryEnd && !isLastWindow) {
        break;
      }
      if (absStart < cursor) {
        continue; // a long match already emitted by the previous window
      }
      // A match touching the (non-final) window edge may be longer than this
      // window revealed; re-resolve it against the full text so it is not clipped.
      if (absStart + matchText.length >= windowEnd && !isLastWindow) {
        anchored.lastIndex = absStart;
        const full = anchored.exec(text);
        if (full && full.index === absStart && full[0].length > matchText.length) {
          matchText = full[0];
        }
      }
      output += text.slice(cursor, absStart);
      output += matchText.replace(single, replacer);
      cursor = absStart + matchText.length;
    }
  }
  output += text.slice(cursor);
  return output;
}
