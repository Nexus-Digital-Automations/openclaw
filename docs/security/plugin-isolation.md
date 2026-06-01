---
summary: Phase-2 design for isolating plugin code from the host Node process. Records why the capability gate is a policy control, not a sandbox, and what real containment would cost.
title: Plugin process isolation (Phase 2 design)
read_when:
  - Evaluating whether OpenClaw sandboxes third-party plugin code
  - Scoping real plugin containment beyond the capability gate
  - Reviewing the plugin runtime's trust boundary
permalink: /security/plugin-isolation/
---

This page is a **design proposal for owner review**, not shipped behavior. It
records the current trust boundary around plugin code and what it would take to
actually contain a malicious or compromised plugin. Phase 1 (the capability
gate) has shipped; Phase 2 (isolation) has not.

## Current state — plugins run in-process, unsandboxed

A plugin is loaded as an ordinary ES module into the **main Node process** (the
loader's `createPluginModuleLoader` → dynamic import) and its `register(api)`
function runs synchronously, receiving **live object references**: the
`PluginRuntime`, the SDK facade, and per-request hook events/contexts. Hook
handlers are stored as plain function references and invoked directly on the
hot path (`createHookRunner` → `runVoidHook` / `runModifyingHook` /
the claiming seams).

Consequence: a plugin has the **same authority as core**. It can
`require("node:child_process")`, read `process.env`, open sockets, and touch the
filesystem regardless of what it declared. The capability gate does not change
this — it is a policy check at the hook-dispatch seam, not an OS or VM boundary.

## What the capability gate does (Phase 1, shipped)

The gate (`passesCapabilityGateOrWarn`) compares each fired hook against the
plugin's declared manifest surface and, for plugins stamped `enforced` (new
external installs), **hard-blocks undeclared hooks**; bundled and grandfathered
plugins stay warn-only. As of this cycle the gate runs at **every dispatch
seam** (void / modifying / claiming), not just `runVoidHook`.

This meaningfully reduces blast radius for plugins that route through the hook
API and raises the bar for accidental over-reach. It does **not** stop a hostile
plugin that simply bypasses the hook API and calls Node built-ins directly. The
gate is defense-in-depth, not the containment boundary.

## Why isolation is a deep change, not a patch

Three properties of the current plugin model each break under process/worker
separation:

1. **Synchronous `register()` contract.** The loader requires `register` to
   complete synchronously; plugins make arbitrary synchronous `api.registerX()`
   calls during it. A process boundary makes every such call an async IPC
   round-trip, forcing an async-first registration API — a breaking change for
   every existing plugin.
2. **Live object references.** Hooks receive real runtime objects (history
   messages, tool params, trace context, `PluginRuntime` helpers) and may call
   back into the runtime mid-hook. Across a boundary, every event and every
   plugin-initiated call must be **serialized both ways**; objects holding
   functions or large payloads do not cross cleanly.
3. **Hot-path dispatch.** Hooks fire on the request path, void hooks in
   parallel. An IPC + (de)serialize round-trip per hook adds latency to the
   critical path and serializes work that is parallel today.

## Chokepoints a boundary would attach to

- **Module load:** the loader's plugin module import — where a worker/process
  would be spawned per plugin (or per trust tier).
- **Registration:** `register(api)` — must become message-based and async.
- **Dispatch:** `createHookRunner` (`runVoidHook` / `runModifyingHook` /
  `runClaimingHooksList` / `runClaimingHookForPluginOutcome`) — the single place
  where events would be serialized out and results merged back in.

## Options (for owner decision)

| Mechanism            | Containment                                  | Cost / risk                                                                                  |
| -------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `worker_threads`     | Separate JS realm, shared-nothing by default | Still same process; native addons and some escapes remain; SharedArrayBuffer needed for perf |
| `child_process` fork | True OS process boundary                     | Highest IPC cost; lifecycle + crash handling; full async API rewrite                         |
| `vm` / isolate       | In-process memory separation                 | Not a security boundary on its own (prototype/`require` escapes); weakest guarantee          |

## Proposed phased migration

1. **Keep the capability gate as the in-process backstop** (done) — it remains
   valuable even after isolation lands.
2. **Define a serializable hook-event contract** for the declared-surface hooks
   so events/results can cross a boundary without live references.
3. **Async-first registration shim:** introduce a message-based `register`
   path behind a compat adapter so existing sync plugins keep working while the
   new API is opt-in (per the SDK compat policy).
4. **Opt-in isolated workers for untrusted/external plugins first**, leaving
   bundled first-party plugins in-process until the contract proves out.
5. **Promote isolation to default** only after the serialized contract covers
   the full hook surface and perf is validated.

## Status

Out of scope for the current security cycle. This requires an owner decision on
the isolation mechanism and an SDK-versioned migration, both of which exceed a
plan-independent hardening pass. Tracked here so the trust boundary is explicit
rather than implied.
