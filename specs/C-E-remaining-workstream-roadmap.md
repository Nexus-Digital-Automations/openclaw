# C + E remaining workstreams — operator roadmap escalation

**Status:** escalated to operator. Multi-week scope captured for execution
across dedicated future sessions; not session-completable.

## What's already shipped (this fork's `main` as of v3 execution)

- **C.1** `758a04f811` — observe-bundled-plugin-hooks tooling
- **C.2** `205e52a590` — getPluginCapabilities runtime accessor
- **C.3 part 1/N** `4b4d216248` — warn-mode gate at runVoidHook dispatch
- **C.5** `2a251cf6e2` — advisory contract test (flips to enforcing as C.6)
- **E.1** `09fe121ad5` — plugin-sdk/http-guard-runtime + pluginFetch
- **E.4** `c5c667d628` — plugin-sdk/fs-guard-runtime + pluginReadFile/Write/ListDir

## What remains, by dependency

```
C.4 backfill (125 manifests)
   ├── blocks C.5 enforcement flip
   └── blocks C.6 strict-enforce flip (warn→throw)

C.3 part 2/N (remaining hook dispatch seams)
   └── no blockers; can interleave with C.4

E.2 bundled-plugin fetch codemod (~50-100 sites)
   ├── blocks E.6 oxlint ban (would fail CI day-one)
   └── blocks E.7 warn-mode adapter

E.3 provider-SDK fetch wrap (Anthropic / OpenAI / Google)
   └── no blockers; can interleave with E.2

E.5 plugin-facing fs helpers codemod
   ├── blocks E.6 oxlint ban (same reason)
   └── blocks E.7 warn-mode adapter

E.6 oxlint bans bare fetch + node:fs
   └── blocks once E.2 + E.5 finish

E.7 warn-mode adapter at both guards
   └── blocks E.8

E.8 strict-enforce flip at both guards
   └── blocks on C.6 (so the warn→throw pattern is proven first)
```

## Per-task realistic-scope sizing

| Task | Realistic effort | Why session-incompatible |
|---|---|---|
| C.4 | ~12-15 commits over days | 125 per-plugin manifest backfills require hand review per plugin to distinguish dev-only hook attachments from production-required ones (the C.1 tooling observes, never decides) |
| C.6 | 1 commit + flip + tests | Hard-blocks on C.4 fully landing; flipping before backfill clears would break every CI run |
| E.2 | ~10 commits over days | ~50-100 bundled-plugin `fetch(` call sites; one commit per ~10 plugins to keep diffs reviewable |
| E.3 | 1-3 commits | Per-SDK investigation: Anthropic / OpenAI / Google may or may not support custom fetch injection; fallback is wrapping at the provider-transport-stream boundary uniformly |
| E.5 | ~5-8 commits | Plugin-facing fs helpers (workspace.read, memory.read, skill loaders) codemod across consumers |
| E.6 | 1 commit | Lands after E.2 + E.5 codemods finish; oxlint rule with `extensions/**/src/**` selector |
| E.7 | 1 commit per guard | Warn-mode adapter wrapping pluginFetch / pluginReadFile etc. with the C.3-style structured warn + counter shape |
| E.8 | 1 commit | Strict-enforce flip after C.6 proves the warn→throw pattern across guards |

## Operator execution checklist (for future sessions)

Session 1 (C.4 batch 1 + C.3 part 2):
1. Run `node scripts/observe-bundled-plugin-hooks.mjs --gaps-only` to inventory
2. Pick 10 simple bundled plugins; hand-review each register() implementation
3. Land 10 manifest backfill commits + push
4. Add `passesCapabilityGateOrWarn` call at `runSyncHookHandler` and
   `runClaimingHooksList` dispatch seams; ship as C.3 part 2/N

Session 2-N (C.4 remaining batches):
- Each session lands one batch of ~10 simple plugins + 1-2 complex plugins
- C.5 advisory test surfaces declining gap count in CI on every commit

Session F (C.6 + C.5 flip):
- Once `--summary` reports 0 missing, ship C.6 commit:
  - Convert `passesCapabilityGateOrWarn` return value from `true` to
    `throw new CapabilityDeniedError(...)`
  - Convert C.5 advisory `console.log` to
    `expect(totals.missing).toBe(0)`
  - Update SECURITY.md item 8 to reflect strict-enforce defaults

Session G (E.2 batch 1):
- Run `grep -rn "fetch(" extensions/**/src/**` to inventory call sites
- Codemod the first ~10 plugins onto `pluginFetch`; ship + push
- Each subsequent session lands another batch

Sessions H+ for E.3, E.5, E.6, E.7, E.8 follow the same per-batch
pattern with explicit dependency tracking from the diagram above.

## Why this can't be one-session work

Even with tooling, every C.4 manifest backfill requires hand review of
the plugin's register() implementation to:
- distinguish dev-only hook attachments from production-required ones
- catch conditional hook registrations the static observer can't see
- verify the manifest declaration matches the actual ship surface

That's ~15-30 min per plugin × 125 plugins = 30-60 hours of focused
review work. Codemods (E.2, E.5) have similar per-site judgment about
which fetch / fs call sites should use the guarded helpers vs which
are intentionally bypassing (e.g. internal infrastructure code).

These are real, important, but explicitly multi-week milestones — not
single-session tasks.
