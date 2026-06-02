# G.1 — HTTP + FS plugin capability runtime enforcement

**Status:** scoped, not implemented. Hook-capability enforcement landed in a
separate milestone (warn-only first); HTTP + FS require infrastructure that
does not exist today.

## What's already shipped

- `src/plugins/capabilities.ts` exports `checkHookCapability`,
  `checkHttpAllowlist`, `checkFsScope` and the `PluginCapabilities` type.
- Plugin manifests can declare `capabilities.{hooks,providers,tools,channels,httpAllowlist,fsScopes}`.
- Install-time signing gate parses and verifies the declared manifest
  (`feat(security): install-gate parses signed plugin capability manifest`).
- Hook-capability runtime enforcement: separate milestone (warn-only first
  pending 127-manifest backfill, then strict).

## What's missing for HTTP + FS

The runtime helpers `checkHttpAllowlist` and `checkFsScope` exist but no
dispatch seam consults them today. Plugins make outbound HTTP via bare
`fetch` or provider-native clients; plugins read/write the workspace via
multiple ad-hoc helpers (`workspace.read`, `memory.read`, skill resolvers,
etc.). There is no central wrapper to wedge a capability check into.

## Required infrastructure

### HTTP — `openclaw/plugin-sdk/http-guard` (new subpath)

- Export a `pluginFetch(input, init, ctx?)` wrapper that, before delegating
  to `globalThis.fetch`, resolves the calling plugin's
  `capabilities.httpAllowlist` and calls `checkHttpAllowlist(...)`. On
  `!ok`, throw `HttpAllowlistDeniedError` and append a
  `plugin.capability.http_denied` audit-chain entry.
- Wire bundled plugins to consume `pluginFetch` instead of bare `fetch`.
  Inventory the call sites (estimate ~50–100 across `extensions/`).
- Deprecate bare `fetch` from plugins via an oxlint rule that bans
  unqualified `fetch(` inside `extensions/**/src/**` and recommends
  `pluginFetch`.
- For provider-native HTTP clients (Anthropic SDK, OpenAI SDK, Google
  GenAI SDK) — those have their own internal `fetch` paths. Either:
  - Inject a custom `fetch` implementation via SDK init options (clean
    seam where supported), or
  - Wrap at the higher-level provider-call boundary inside the OpenClaw
    provider transport (`src/agents/*-transport-stream.ts`) — coarser but
    covers all SDKs uniformly. Pick one strategy in the implementation
    commit.

### FS — `openclaw/plugin-sdk/fs-guard` (new subpath)

- Export a `pluginReadFile`, `pluginWriteFile`, `pluginListDir` family
  that resolves the plugin's `capabilities.fsScopes`, normalizes the
  target path against the plugin's allowed roots, and rejects with
  `FsScopeDeniedError` on miss. Append
  `plugin.capability.fs_denied` audit-chain entry.
- Existing plugin-facing fs helpers (`workspace.read`, `memory.read`,
  skill loaders) consume `fs-guard` internally. The seam is opaque to
  plugin authors who use the higher-level helpers — they get
  capability enforcement for free.
- Plugins that bypass the helpers and reach for `node:fs` directly are
  flagged by an oxlint rule banning `import.*from\\s+["']node:fs`
  inside `extensions/**/src/**`.

## Migration plan

1. **Land the SDK surfaces** — `http-guard` + `fs-guard` exposed via
   `scripts/lib/plugin-sdk-entrypoints.json`, `package.json` exports,
   `src/plugin-sdk/entrypoints.ts`. Docs in `docs/plugins/sdk-overview.md`.
2. **Codemod bundled plugins** — replace bare `fetch` / `node:fs`
   imports with the guarded equivalents. One commit per plugin where
   the change is non-trivial; bulk for one-liners.
3. **Warn-only enforcement** — both guards log
   `plugin.capability.http_violation_observed` / `..._fs_violation_observed`
   with structured warn + counter increment but proceed. Same shape as
   the hook-capability rollout.
4. **Manifest backfill** — declare `httpAllowlist` + `fsScopes` on every
   bundled plugin manifest based on the observed violations from step 3.
5. **Flip to strict** — convert warn → throw + `plugin.capability.denied`.
   Land alongside the hook-capability strict flip.

## Effort estimate

- HTTP: 2–3 weeks (SDK surface + codemod + provider SDK custom-fetch
  injection + bundled-plugin backfill + tests). Highest cost is the
  provider-SDK fetch injection — not all SDKs support it cleanly.
- FS: 1–2 weeks (SDK surface + codemod of the ~6 plugin-facing fs
  helpers + lint rule + tests).

Both depend on the manifest-backfill tooling from the capability
milestone landing first (operators need declared scopes before strict
enforcement is meaningful).

## What ships in the meantime

- Declarations are verified at install time (already shipped). A
  malicious plugin cannot ship with hidden HTTP/FS access — the manifest
  has to declare what it intends to do, and the install gate refuses
  unsigned or tampered manifests.
- Hook-capability enforcement (separate milestone) provides the proof
  that runtime capability checks integrate cleanly with the existing
  dispatch seams.
- The output firewall + external-content wrap + HITL gate continue to
  cover the laundering channels an attacker would use to drive a plugin
  into unintended HTTP/FS calls.

The gap relative to a full G.1: a signed first-party plugin with broad
`httpAllowlist` declared but selectively-malicious behavior at runtime
(e.g. exfil to a declared allowlist host only on tuesdays). Capability
declarations cap the surface; runtime enforcement plus seccomp-in-microvm
(see `specs/F-microvm-sandbox-escalation.md`) closes it.

## Decision needed before implementation

1. Provider SDK fetch injection — custom fetch per SDK, or wrap at the
   provider-transport-stream layer uniformly?
2. FS guard scope — does it cover skills-resolver path resolution too,
   or only direct plugin fs helpers? (Skills resolver is a different
   trust boundary.)
3. Rollout cadence — bundled-plugin codemod before or after the
   bundled-manifest backfill?

These shape the implementation scope and should be answered in a
focused planning conversation before any code lands.
