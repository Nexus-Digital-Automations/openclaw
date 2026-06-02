/**
 * Owner: security/aho-corasick.
 *
 * Pure Aho-Corasick automaton primitive shared by the output firewall
 * (streaming, stateful caller) and the tool-output redactor (batch,
 * per-string-stateless caller).
 *
 * What is pure here: trie construction, failure-link wiring, character-step
 * transitions. No I/O. No mutation of inputs after compile returns.
 *
 * What is NOT here: match-collection strategy (first-trip vs. all-matches),
 * state lifecycle (persist across chunks vs. reset per string), and pattern
 * filtering policy (callers apply their own min-length floor before passing
 * entries in).
 *
 * Lifecycle distinction:
 * - Streaming caller (output firewall): compile once per turn, keep the node
 *   returned by stepAc across successive scan() calls so partial matches that
 *   straddle chunk boundaries are detected.
 * - Batch caller (tool-output redactor): compile once per turn, call stepAc
 *   from compiled.root at the start of each string and discard the frontier
 *   node between strings.
 */

export type FamilyTag = string;

export type AcNode<F extends FamilyTag = FamilyTag> = {
  next: Map<number, AcNode<F>>;
  fail: AcNode<F> | null;
  outputs: ReadonlyArray<{ literal: string; family: F }>;
};

export type CompiledAC<F extends FamilyTag = FamilyTag> = {
  root: AcNode<F>;
  patternCount: number;
};

/**
 * Compile a set of pattern entries into an Aho-Corasick automaton.
 * Entries with literal.length < minPatternLength are silently dropped.
 * Returns an automaton with patternCount === 0 when no entries survive the
 * filter — callers may choose to use an inert path in that case.
 */
export function compileAc<F extends FamilyTag>(
  entries: ReadonlyArray<{ literal: string; family: F }>,
  minPatternLength = 1,
): CompiledAC<F> {
  const root = makeNode<F>();
  let count = 0;
  for (const entry of entries) {
    if (entry.literal.length < minPatternLength) {
      continue;
    }
    insertIntoTrie(root, entry);
    count++;
  }
  wireFailureLinks(root);
  return { root, patternCount: count };
}

/**
 * Advance the automaton one character. The caller owns the current node and
 * must pass it back on the next call to maintain streaming state.
 *
 * Returns the new frontier node plus ALL patterns that end at this position
 * (direct outputs union fail-link cascade). An empty matches array means no
 * pattern ended here — it is a domain-correct "no match", not an error.
 */
export function stepAc<F extends FamilyTag>(
  compiled: CompiledAC<F>,
  current: AcNode<F>,
  charCode: number,
): { node: AcNode<F>; matches: ReadonlyArray<{ literal: string; family: F }> } {
  const node = advanceNode(compiled.root, current, charCode);
  return { node, matches: node.outputs };
}

// --- internal helpers ---

function makeNode<F extends FamilyTag>(): AcNode<F> {
  return { next: new Map(), fail: null, outputs: [] };
}

function insertIntoTrie<F extends FamilyTag>(
  root: AcNode<F>,
  entry: { literal: string; family: F },
): void {
  let cur = root;
  for (let i = 0; i < entry.literal.length; i++) {
    const code = entry.literal.charCodeAt(i);
    let child = cur.next.get(code);
    if (child === undefined) {
      child = makeNode<F>();
      cur.next.set(code, child);
    }
    cur = child;
  }
  // outputs is ReadonlyArray in the public type; cast to mutable only here
  (cur.outputs as Array<{ literal: string; family: F }>).push(entry);
}

function wireFailureLinks<F extends FamilyTag>(root: AcNode<F>): void {
  const queue: AcNode<F>[] = [];
  for (const child of root.next.values()) {
    child.fail = root;
    queue.push(child);
  }
  while (queue.length > 0) {
    const node = queue.shift() as AcNode<F>;
    for (const [code, child] of node.next) {
      queue.push(child);
      child.fail = resolveFailTarget(root, node.fail, code);
      // Propagate fail-link outputs so stepAc only needs to read node.outputs.
      const mutable = child.outputs as Array<{ literal: string; family: F }>;
      for (const output of child.fail.outputs) {
        mutable.push(output);
      }
    }
  }
}

function resolveFailTarget<F extends FamilyTag>(
  root: AcNode<F>,
  start: AcNode<F> | null,
  code: number,
): AcNode<F> {
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

function advanceNode<F extends FamilyTag>(
  root: AcNode<F>,
  from: AcNode<F>,
  code: number,
): AcNode<F> {
  let cursor: AcNode<F> | null = from;
  while (cursor !== null) {
    const next = cursor.next.get(code);
    if (next !== undefined) {
      return next;
    }
    cursor = cursor.fail;
  }
  return root;
}
