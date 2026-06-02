type QuantifierRead = {
  consumed: number;
  minRepeat: number;
  maxRepeat: number | null;
};

type TokenState = {
  containsRepetition: boolean;
  hasAmbiguousAlternation: boolean;
  // Whether this token is an alternation group whose branches can match the same
  // first character — equal-length-but-overlapping branches (e.g. `(a|a)`) that
  // the length model alone treats as unambiguous but cause exponential ReDoS
  // under an unbounded quantifier.
  hasOverlappingAlternation: boolean;
  minLength: number;
  maxLength: number;
  // Character signature of the single character this token can begin with, used
  // to detect overlap between adjacent unbounded quantifiers (`\d+\d+`, `.*.*`).
  // Empty for groups/multi-shape tokens, which are treated as non-overlapping.
  sig: string;
  // Set when the immediately-preceding token was quantified with an unbounded
  // upper bound; carries that token's sig so a second unbounded quantifier here
  // can detect overlap.
  precedingUnboundedSig: string | null;
};

type ParseFrame = {
  lastToken: TokenState | null;
  containsRepetition: boolean;
  hasAlternation: boolean;
  branchMinLength: number;
  branchMaxLength: number;
  altMinLength: number | null;
  altMaxLength: number | null;
  // First-character sig of the current alternation branch, and the collected
  // first-sigs of all branches seen so far, for overlap detection on close.
  branchFirstSig: string | null;
  branchFirstSigs: string[];
  // Sig of the most recent token quantified with an unbounded upper bound, so an
  // adjacent unbounded quantifier can detect overlap.
  lastUnboundedSig: string | null;
};

type PatternToken =
  | { kind: "simple-token"; sig: string }
  | { kind: "group-open" }
  | { kind: "group-close" }
  | { kind: "alternation" }
  | { kind: "quantifier"; quantifier: QuantifierRead };

const SAFE_REGEX_CACHE_MAX = 256;
const SAFE_REGEX_TEST_WINDOW = 2048;
export type SafeRegexRejectReason = "empty" | "unsafe-nested-repetition" | "invalid-regex";

export type SafeRegexCompileResult =
  | {
      regex: RegExp;
      source: string;
      flags: string;
      reason: null;
    }
  | {
      regex: null;
      source: string;
      flags: string;
      reason: SafeRegexRejectReason;
    };

const safeRegexCache = new Map<string, SafeRegexCompileResult>();

function createParseFrame(): ParseFrame {
  return {
    lastToken: null,
    containsRepetition: false,
    hasAlternation: false,
    branchMinLength: 0,
    branchMaxLength: 0,
    altMinLength: null,
    altMaxLength: null,
    branchFirstSig: null,
    branchFirstSigs: [],
    lastUnboundedSig: null,
  };
}

// Whether two single-character signatures can match the same character. Sound
// (no false negatives) for identity; `.` matches anything; `\w` is a superset of
// `\d`. Conservative elsewhere — two distinct literals/classes are treated as
// disjoint, so legitimate patterns like `\d+[a-z]+` or `(foo|bar)+` are not
// rejected. Empty sig (groups) never overlaps.
function sigsOverlap(a: string | null, b: string | null): boolean {
  if (!a || !b) {
    return false;
  }
  if (a === b) {
    return true;
  }
  if (a === "." || b === ".") {
    return true;
  }
  const broad = new Set(["\\w", "\\W", "\\S"]);
  if ((a === "\\w" && b === "\\d") || (b === "\\w" && a === "\\d")) {
    return true;
  }
  return broad.has(a) && broad.has(b);
}

// Read a `[...]` class span starting at `[` (index points at `[`), respecting
// `\]`. Returns the full source slice so two identical classes share a sig.
function readCharClassSpan(source: string, openIndex: number): string {
  let i = openIndex + 1;
  while (i < source.length) {
    if (source[i] === "\\") {
      i += 2;
      continue;
    }
    if (source[i] === "]") {
      return source.slice(openIndex, i + 1);
    }
    i += 1;
  }
  return source.slice(openIndex);
}

function addLength(left: number, right: number): number {
  if (!Number.isFinite(left) || !Number.isFinite(right)) {
    return Number.POSITIVE_INFINITY;
  }
  return left + right;
}

function multiplyLength(length: number, factor: number): number {
  if (!Number.isFinite(length)) {
    return factor === 0 ? 0 : Number.POSITIVE_INFINITY;
  }
  return length * factor;
}

function recordAlternative(frame: ParseFrame): void {
  if (frame.altMinLength === null || frame.altMaxLength === null) {
    frame.altMinLength = frame.branchMinLength;
    frame.altMaxLength = frame.branchMaxLength;
    return;
  }
  frame.altMinLength = Math.min(frame.altMinLength, frame.branchMinLength);
  frame.altMaxLength = Math.max(frame.altMaxLength, frame.branchMaxLength);
}

function readQuantifier(source: string, index: number): QuantifierRead | null {
  const ch = source[index];
  const consumed = source[index + 1] === "?" ? 2 : 1;
  if (ch === "*") {
    return { consumed, minRepeat: 0, maxRepeat: null };
  }
  if (ch === "+") {
    return { consumed, minRepeat: 1, maxRepeat: null };
  }
  if (ch === "?") {
    return { consumed, minRepeat: 0, maxRepeat: 1 };
  }
  if (ch !== "{") {
    return null;
  }

  let i = index + 1;
  while (i < source.length && /\d/.test(source[i])) {
    i += 1;
  }
  if (i === index + 1) {
    return null;
  }

  const minRepeat = Number.parseInt(source.slice(index + 1, i), 10);
  let maxRepeat: number | null = minRepeat;
  if (source[i] === ",") {
    i += 1;
    const maxStart = i;
    while (i < source.length && /\d/.test(source[i])) {
      i += 1;
    }
    maxRepeat = i === maxStart ? null : Number.parseInt(source.slice(maxStart, i), 10);
  }

  if (source[i] !== "}") {
    return null;
  }
  i += 1;
  if (source[i] === "?") {
    i += 1;
  }
  if (maxRepeat !== null && maxRepeat < minRepeat) {
    return null;
  }

  return { consumed: i - index, minRepeat, maxRepeat };
}

function tokenizePattern(source: string): PatternToken[] {
  const tokens: PatternToken[] = [];
  let inCharClass = false;

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];

    if (inCharClass) {
      if (ch === "\\") {
        i += 1;
        continue;
      }
      if (ch === "]") {
        inCharClass = false;
      }
      continue;
    }

    if (ch === "\\") {
      i += 1;
      tokens.push({ kind: "simple-token", sig: `\\${source[i] ?? ""}` });
      continue;
    }

    if (ch === "[") {
      inCharClass = true;
      tokens.push({ kind: "simple-token", sig: readCharClassSpan(source, i) });
      continue;
    }

    if (ch === "(") {
      tokens.push({ kind: "group-open" });
      continue;
    }

    if (ch === ")") {
      tokens.push({ kind: "group-close" });
      continue;
    }

    if (ch === "|") {
      tokens.push({ kind: "alternation" });
      continue;
    }

    const quantifier = readQuantifier(source, i);
    if (quantifier) {
      tokens.push({ kind: "quantifier", quantifier });
      i += quantifier.consumed - 1;
      continue;
    }

    tokens.push({ kind: "simple-token", sig: ch });
  }

  return tokens;
}

function anyBranchSigsOverlap(sigs: readonly string[]): boolean {
  for (let i = 0; i < sigs.length; i += 1) {
    for (let j = i + 1; j < sigs.length; j += 1) {
      if (sigsOverlap(sigs[i], sigs[j])) {
        return true;
      }
    }
  }
  return false;
}

function analyzeTokensForNestedRepetition(tokens: PatternToken[]): boolean {
  const frames: ParseFrame[] = [createParseFrame()];

  const emitToken = (token: TokenState) => {
    const frame = frames[frames.length - 1];
    // Adjacency for `\d+\d+`: this token inherits the sig of the immediately
    // preceding unbounded quantifier exactly once, then the carry is cleared.
    token.precedingUnboundedSig = frame.lastUnboundedSig;
    frame.lastUnboundedSig = null;
    if (frame.branchFirstSig === null) {
      frame.branchFirstSig = token.sig;
    }
    frame.lastToken = token;
    if (token.containsRepetition) {
      frame.containsRepetition = true;
    }
    frame.branchMinLength = addLength(frame.branchMinLength, token.minLength);
    frame.branchMaxLength = addLength(frame.branchMaxLength, token.maxLength);
  };

  const emitSimpleToken = (sig: string) => {
    emitToken({
      containsRepetition: false,
      hasAmbiguousAlternation: false,
      hasOverlappingAlternation: false,
      minLength: 1,
      maxLength: 1,
      sig,
      precedingUnboundedSig: null,
    });
  };

  for (const token of tokens) {
    if (token.kind === "simple-token") {
      emitSimpleToken(token.sig);
      continue;
    }

    if (token.kind === "group-open") {
      frames.push(createParseFrame());
      continue;
    }

    if (token.kind === "group-close") {
      if (frames.length > 1) {
        const frame = frames.pop() as ParseFrame;
        if (frame.hasAlternation) {
          recordAlternative(frame);
          frame.branchFirstSigs.push(frame.branchFirstSig ?? "");
        }
        const groupMinLength = frame.hasAlternation
          ? (frame.altMinLength ?? 0)
          : frame.branchMinLength;
        const groupMaxLength = frame.hasAlternation
          ? (frame.altMaxLength ?? 0)
          : frame.branchMaxLength;
        emitToken({
          containsRepetition: frame.containsRepetition,
          hasAmbiguousAlternation:
            frame.hasAlternation &&
            frame.altMinLength !== null &&
            frame.altMaxLength !== null &&
            frame.altMinLength !== frame.altMaxLength,
          hasOverlappingAlternation:
            frame.hasAlternation && anyBranchSigsOverlap(frame.branchFirstSigs),
          minLength: groupMinLength,
          maxLength: groupMaxLength,
          sig: "", // a group's single-char start is unknown; treated as non-overlapping
          precedingUnboundedSig: null,
        });
      }
      continue;
    }

    if (token.kind === "alternation") {
      const frame = frames[frames.length - 1];
      frame.hasAlternation = true;
      recordAlternative(frame);
      frame.branchFirstSigs.push(frame.branchFirstSig ?? "");
      frame.branchFirstSig = null;
      frame.branchMinLength = 0;
      frame.branchMaxLength = 0;
      frame.lastToken = null;
      continue;
    }

    const frame = frames[frames.length - 1];
    const previousToken = frame.lastToken;
    if (!previousToken) {
      continue;
    }
    const unbounded = token.quantifier.maxRepeat === null;
    if (previousToken.containsRepetition) {
      return true;
    }
    if (previousToken.hasAmbiguousAlternation && unbounded) {
      return true;
    }
    // M6: equal-length-but-overlapping alternation under an unbounded quantifier
    // (e.g. `(a|a)+`) — the length model treats it as unambiguous, but the shared
    // first character drives exponential backtracking.
    if (previousToken.hasOverlappingAlternation && unbounded) {
      return true;
    }
    // M7: two adjacent unbounded quantifiers over overlapping character sets
    // (`\d+\d+`, `.*.*`) — polynomial backtracking the length model misses.
    if (unbounded && sigsOverlap(previousToken.precedingUnboundedSig, previousToken.sig)) {
      return true;
    }
    if (unbounded) {
      frame.lastUnboundedSig = previousToken.sig;
    }

    const previousMinLength = previousToken.minLength;
    const previousMaxLength = previousToken.maxLength;
    previousToken.minLength = multiplyLength(previousToken.minLength, token.quantifier.minRepeat);
    previousToken.maxLength =
      token.quantifier.maxRepeat === null
        ? Number.POSITIVE_INFINITY
        : multiplyLength(previousToken.maxLength, token.quantifier.maxRepeat);
    previousToken.containsRepetition = true;
    frame.containsRepetition = true;
    frame.branchMinLength = frame.branchMinLength - previousMinLength + previousToken.minLength;

    const branchMaxBase =
      Number.isFinite(frame.branchMaxLength) && Number.isFinite(previousMaxLength)
        ? frame.branchMaxLength - previousMaxLength
        : Number.POSITIVE_INFINITY;
    frame.branchMaxLength = addLength(branchMaxBase, previousToken.maxLength);
  }

  return false;
}

function testRegexFromStart(regex: RegExp, value: string): boolean {
  regex.lastIndex = 0;
  return regex.test(value);
}

export function testRegexWithBoundedInput(
  regex: RegExp,
  input: string,
  maxWindow = SAFE_REGEX_TEST_WINDOW,
): boolean {
  if (maxWindow <= 0) {
    return false;
  }
  if (input.length <= maxWindow) {
    return testRegexFromStart(regex, input);
  }
  const head = input.slice(0, maxWindow);
  if (testRegexFromStart(regex, head)) {
    return true;
  }
  return testRegexFromStart(regex, input.slice(-maxWindow));
}

export function hasNestedRepetition(source: string): boolean {
  // Conservative parser: tokenize first, then check if repeated tokens/groups are repeated again.
  // Non-goal: complete regex AST support; keep strict enough for config safety checks.
  return analyzeTokensForNestedRepetition(tokenizePattern(source));
}

export function compileSafeRegexDetailed(source: string, flags = ""): SafeRegexCompileResult {
  const trimmed = source.trim();
  if (!trimmed) {
    return { regex: null, source: trimmed, flags, reason: "empty" };
  }
  const cacheKey = `${flags}::${trimmed}`;
  if (safeRegexCache.has(cacheKey)) {
    return (
      safeRegexCache.get(cacheKey) ?? {
        regex: null,
        source: trimmed,
        flags,
        reason: "invalid-regex",
      }
    );
  }

  let result: SafeRegexCompileResult;
  if (hasNestedRepetition(trimmed)) {
    result = { regex: null, source: trimmed, flags, reason: "unsafe-nested-repetition" };
  } else {
    try {
      result = { regex: new RegExp(trimmed, flags), source: trimmed, flags, reason: null };
    } catch {
      result = { regex: null, source: trimmed, flags, reason: "invalid-regex" };
    }
  }

  safeRegexCache.set(cacheKey, result);
  if (safeRegexCache.size > SAFE_REGEX_CACHE_MAX) {
    const oldestKey = safeRegexCache.keys().next().value;
    if (oldestKey) {
      safeRegexCache.delete(oldestKey);
    }
  }
  return result;
}

export function compileSafeRegex(source: string, flags = ""): RegExp | null {
  return compileSafeRegexDetailed(source, flags).regex;
}
