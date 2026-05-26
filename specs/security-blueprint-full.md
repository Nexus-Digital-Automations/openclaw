# Security Blueprint — Full Implementation Spec

**Scope:** all 22 controls from `plans/here-is-your-ultimate-scalable-mitten.md`, Phase 1 + 2 + 3.
**Gating:** always-on; no `hardened_mode` flag.
**Validation:** `tsgo:core` + `tsgo:test:src` + `scripts/run-vitest.mjs` + `scripts/run-oxlint.mjs` per touched file. Skip broad `pnpm check:changed` (Crabbox-scope per AGENTS.md).
**Owner gate:** lifted (fork owner = user).

## Already shipped (origin/main d2e9f91cec..3c6c9aa2ea)

- Per-session resolved-secret cache populated in `secrets/resolve.ts:893`; literal-aware redactor (`logging/redact.ts`)
- External-content `source="..."` start-marker attribute (`security/external-content.ts`)
- Shell-spawn audit (`security/audit-shell-spawn-policy.test.ts`); exec-safe-bin allowlist snapshot
- `plugins/skills-lock.ts` + `.runtime.ts` (module exists, not yet wired into install flow)
- `agents/workspace-zones.ts` (classifier exists, no callers yet)

## Phase 1 — wire existing primitives

### 1.A — skills.lock end-to-end

- `openclaw plugins lock` CLI: walks installed plugin dirs, computes hashes, writes lockfile (the existing `skills` namespace is workspace ClawHub skills — different domain; plugin integrity belongs under `plugins`)
- `openclaw plugins verify` CLI: reads lockfile, runs `verifyPluginAgainstLock` per plugin, exits non-zero on mismatch
- Install/enable flow refuses plugin on `SkillsLockVerificationError`
- `security/audit-plugins-trust.ts` `plugins.installs_missing_integrity` flips `warn → critical` when lockfile present and skip occurred

**Acceptance:** `openclaw skills lock` then mutating any byte in a plugin file then `openclaw skills verify` exits non-zero with named file. Plugin enable refuses on tamper.

### 1.B — workspace-zones consumers

- File-read tools (Read tool dispatch in `agents/bash-tools.*` or equivalent) auto-wrap untrusted-zone bytes via `wrapExternalContent`
- Skill resolver in `security/audit-workspace-skills.ts` refuses any skill resolved from an untrusted-zone root; emits new finding id `skills.zone.untrusted_resolution`

**Acceptance:** dropping a skill into `~/.openclaw/untrusted/skills/` makes resolver refuse with the new finding. Reading a file under that path through the Read-tool dispatch returns content wrapped in external-content markers.

### 1.C — session secret cache → redactor at runtime

- The cache from Phase 0.1 is populated but not yet _read_ by the runtime redactor. Wire it: each log-sink invocation that already calls `redactSecrets` now also passes the session's `resolvedValues` set via `redactSecretsWithLiterals`.

**Acceptance:** a custom-format secret resolved via `resolveSecretRefValue` is masked in transcript, gateway logs, and approval-channel messages even when no regex matches it.

### 1.D — HITL approval on external-content argv

- In `agents/bash-tools.exec-approval-request.ts` (or current equivalent), inspect the resolved argv for substrings that originated in any active external-content block of the current session. If found, force approval-required regardless of bin allowlist.

**Acceptance:** a synthetic external-content string like `EXT-CONTENT-MARKER-123` embedded in a tool call's argv triggers approval even for `git`, which is normally auto-allowed.

### 1.E — memory origin metadata — DEFERRED

Status: **deferred**. The spec assumed a public write API existed in
`packages/memory-host-sdk` that could be additively extended. Discovery during
implementation found:

1. No public write API. Memory writes flow through internal file-watcher sync
   and embedding ops on `MemoryIndexManager`'s private methods. Adding origin
   metadata at write time requires inventing a new public surface, not
   extending one.
2. Persistence is SQLite (`chunks` table). Adding `origin` + `sourceSessionId`
   columns is a schema migration with rollback considerations.
3. The prompt-section builder returns `string[]` — per-snippet wrap requires
   refactoring the contract to surface metadata, which is a breaking change
   for external plugin consumers of the SDK.

These are real changes worth doing, but each is on the order of a separate
multi-commit effort with SDK versioning. Recording the gap here; revisit
when the user wants to plan the API design explicitly.

**Concrete acceptance still applicable when this is picked up:** a memory
entry written with `origin: "untrusted"` is wrapped in the system prompt; reads
of legacy entries (no origin) act as `trusted`.

### 1.F — per-tool-call nonce echo gate — DEFERRED

Status: **deferred**. The plan said "reuse `hasExpectedToolNonce`" from the
gateway liveness probe. Discovery showed the function shape is wrong for this
use case:

1. The probe util tests whether a gateway-injected nonce round-trips through
   a tool the gateway itself controls. There's no model output watcher.
2. Watching model free-text means per-transport state-machine modification
   in `openai-transport-stream.ts`, `anthropic-transport-stream.ts`, and
   `extensions/google/transport-stream.ts` — three large stream handlers,
   not one shared seam.
3. Every simplification (post-response scan, hidden tool-descriptor field,
   synthetic injection prompt) removes most of the defense value or hits
   prompt-cache breakage.

**The structurally adjacent control is Phase 2.A — the output firewall.** It
has the same "scan model output" shape but doesn't require per-tool-call
nonce design; it scans against an already-canonical literal set (process
secrets + external-content bodies). Building 2.A makes 1.F a thin layer on
top later: same scanner, extra literals.

Acceptance still applicable when picked up: synthetic injection that echoes
a nonce verbatim rejects the tool call.

## Phase 2 — significant architecture

### 2.A — output firewall

- New `agents/output-firewall.ts`: streaming Aho-Corasick over the union of `{ session.resolvedValues, session.activeNonces, session.externalContentMarkerBodies }`. Pure module, no IO; takes a chunk + state.
- Hook into `agents/openai-transport-stream.ts`, `agents/anthropic-transport-stream.ts`, `extensions/google/transport-stream.ts` at each `updateOutput()`. On hit: abort stream, surface a redacted rejection.

**Acceptance:** seed a secret into a streamed model response in each transport's test; stream aborts and surface is masked.

### 2.B — micro-VM sandbox backend

- New `agents/sandbox/microvm.ts` implementing `SandboxBackend`. Firecracker on Linux, `Virtualization.framework` on macOS. Windows defers to docker.
- New audit `security/audit-sandbox-microvm-config.test.ts` mirroring docker variant.

**Acceptance:** backend selectable via `gateway.sandbox.backend = "microvm"`; audit passes default config; runs a no-op `echo hello` under the sandbox in the smoke test.

### 2.C — security-sandwich plugin

- `plugins/builtin-security-sandwich.ts`: first-party plugin registering on `before_prompt_build`, `before_tool_call`, `message_sending` pi-agent-core hooks. Bundles Phase 1.A/B/C/D/F enforcement as a single coherent unit.
- Disabling the plugin restores legacy behavior. Snapshot proof: byte-identical pre-Phase-1 system prompt.

**Acceptance:** integration test toggling the plugin produces the byte-identical snapshot; with plugin enabled, all Phase 1 enforcements engage.

**Hook-surface contract locked.** The three required hook names and their
mutation/abort result shapes are now guarded by
`src/plugins/security-sandwich-hook-surface.test.ts`. If pi-agent-core ever
renames one of `before_prompt_build`, `before_tool_call`, `message_sending`
or weakens the result types (drops `systemPrompt`/`block`+`blockReason`/
`cancel`+`cancelReason`+`content`), that test fails and the gap surfaces
before the plugin gets built. 2.C is no longer blocked on contract unknowns.

## Phase 3 — architectural-fight items (do anyway per directive)

The plan explicitly recommended against these. User said "all of it." Implementing on best-effort terms; flagging boundaries that require pi-agent-core SDK changes (which OpenClaw does not own — will be vendored or scaffolded in this fork).

### 3.A — asymmetric trust split (worker + controller)

- Two LLM roles per turn: a `worker` that handles untrusted content, a `controller` that approves tool calls and message-sends. Mediated by `agents/agent-command.ts` orchestration.
- ~2× per-turn model cost; prompt-cache impact accepted.

**Boundary:** requires wrapping `runEmbeddedPiAgent` to run two pi-agent-core instances with cross-mediated message flow. Will scaffold the orchestration shim inside OpenClaw; the SDK itself stays unforked.

**Acceptance:** a model output that asks `worker` to exfiltrate is intercepted by `controller` before tool dispatch.

### 3.B — schema fuzzing (per-turn tool name rotation)

- Per-turn random rename of tool names in `agents/pi-tools.ts:createOpenClawCodingTools`; reverse map in dispatch handler.
- Breaks Anthropic/OpenAI tool-grammar caching (documented in spec).

**Acceptance:** two consecutive runs with the same prompt produce different on-the-wire tool names; dispatch still resolves correctly.

### 3.C — `verified_cmd` envelope

- New tool-call envelope schema layered above pi-agent-core's tool-call protocol. Carries nonce + provenance + hash chain.

**Boundary:** the underlying SDK protocol stays unchanged; the envelope is opaque payload from the SDK's perspective and gets unwrapped in OpenClaw's dispatch path.

**Acceptance:** envelope chain validation refuses any dispatch where nonce/provenance/hash doesn't match the originating turn.

### 3.D — context purification (passive recompilation)

- After each turn, a second model pass that strips anything not in a known-trusted whitelist before the context is fed forward. Effectively a second model invocation per turn.

**Acceptance:** untrusted-marker content present after turn N is absent in the rebuilt context for turn N+1; trusted content survives intact.

## Cross-cutting validation

- Each commit: `pnpm tsgo:core` + `pnpm tsgo:test:src` exit 0; `scripts/run-oxlint.mjs` clean on touched files; `node scripts/run-vitest.mjs <touched-file>` exit 0.
- Per-commit message format: conventional, scoped, single-line subject; commit via `scripts/committer`.
- No bundled SECURITY.md edits (out of scope; existing threat model stays the upstream doc).
- Push to `origin/main` after every successful logical group (typically Phase letter).
- Prompt-cache determinism per AGENTS.md: every map/set iteration order touching the prompt path stays deterministic.

## Out of scope explicitly

- Editing upstream `SECURITY.md` (this is a fork; do not pretend to revise upstream's threat model).
- Forking pi-agent-core (Phase 3 SDK boundaries are scaffolded in-fork only).
- Crabbox/Testbox runs (per AGENTS.md, deferred to the maintainer outside this session).
- Filing issues on `openclaw/openclaw` (this fork stands alone).

## Risk register

- **Phase 3.A/3.D** double per-turn cost. Mitigate: ship behind a per-session opt-out env var even though no flag elsewhere.
- **Phase 3.B** defeats provider tool-grammar caching. Mitigate: limit rotation surface to tool _names_, not schemas.
- **Phase 1.D** could over-fire approval for benign argv strings if external-content markers are too coarse. Mitigate: require minimum substring length and exact-match on body bytes, not marker IDs.
- **Phase 2.A** Aho-Corasick build on every chunk would dominate CPU. Mitigate: rebuild on registry mutation only, cache per session.
- **Volume risk**: ~30-50 commits. Stop-hook will fire repeatedly. User has been briefed.
