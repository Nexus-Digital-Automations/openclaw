const REDACT_REGEX_CHUNK_THRESHOLD = 32_768;
const REDACT_REGEX_CHUNK_SIZE = 16_384;

type BoundedRedactOptions = {
  chunkThreshold?: number;
  chunkSize?: number;
};

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
 * drift. Matches longer than `chunkSize` (no secret/PEM pattern reaches 16 KiB)
 * are the only residual split risk and stay bounded by that constant.
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
  if (!pattern.global) {
    // Without /g, .replace only touches the first match; chunking cannot help and
    // could split that match across a boundary, so scan the whole string.
    return text.replace(pattern, replacer);
  }

  // Non-global, non-sticky clone used to render each owned match in isolation.
  // A single match string replaced by a first-match regex yields identical group
  // args to the caller without depending on any shared `lastIndex` state.
  const single = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ""));
  let output = "";
  let cursor = 0; // next un-emitted index in `text`
  for (let base = 0; base < text.length; base += chunkSize) {
    const windowEnd = Math.min(base + chunkSize * 2, text.length);
    const window = text.slice(base, windowEnd);
    const primaryEnd = base + chunkSize;
    const isLastWindow = windowEnd >= text.length;
    for (const match of window.matchAll(pattern)) {
      const matchText = match[0];
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
      output += text.slice(cursor, absStart);
      output += matchText.replace(single, replacer);
      cursor = absStart + matchText.length;
    }
  }
  output += text.slice(cursor);
  return output;
}
