# F.1/F.2 + G.1#24 — Micro-VM sandbox + seccomp: explicit escalation

**Status:** escalated to user — not implementable in a single coding session.

## Scope summary

The deferred items from `specs/security-blueprint-full.md` Track F and G.1 task #24:

- F.1 — `microvm-backend.ts` implementing `SandboxBackendHandle` with:
  - Linux: Firecracker via `firecracker` binary + jailer
  - macOS: Virtualization.framework via a bundled Swift helper
  - Windows: register but defer to docker backend
- F.2 — registration in `src/agents/sandbox/backend.ts` + extension of
  `SandboxConfig.backend` enum to include `"microvm"` + new
  `audit-sandbox-microvm-config.test.ts`
- G.1 #24 — seccomp profile applied to plugin worker processes,
  derived from the capability manifest landed in commit
  `feat(security): plugin capability manifest primitive (G.1 part 1/3)`

## Why this is escalated, not deferred

These are not the same shape as the other "primitive-first / wire-up
follow-up" splits in this session's commits. Each line item is real
infrastructure work:

### Firecracker (Linux)
- Bundle decision: build-time dependency on the `firecracker` binary
  (operator installs externally?) vs vendoring a pinned version?
- Jailer process model: openclaw spawns jailer per VM? per session?
- Rootfs sourcing: minimal Alpine + Node? something else?
- Network: 9P workspace mount, virtio-net deny-by-default egress, tap
  device lifecycle, dhcp inside the guest
- Boot latency: cold boot is ~125ms for Firecracker; pooling is needed
  to stay in the docker-backend-class user experience
- Multi-week effort even for a competent infrastructure engineer.

### Virtualization.framework (macOS)
- Requires a small **Swift helper binary** bundled with the fork (Node
  can't call the framework directly). That helper has its own:
  - Code-signing identity (entitlement: `com.apple.security.virtualization`)
  - Build pipeline (Xcode + xcrun) integrated into the openclaw
    release pipeline
  - IPC contract to the Node parent (stdio JSON-RPC? unix socket?)
- VirtioFS workspace mount needs a separate decision (rsync overlay?
  read-only base + writable overlay?)
- macOS-only build artifact — needs CI runner support

### Seccomp (Linux, inside the micro-VM)
- Depends entirely on F.1 because the syscall filter lives in the guest
  init or in the jailer's exec wrap
- Mapping the `PluginCapabilities` manifest fields to a concrete
  syscall allowlist is non-trivial — e.g. `httpAllowlist` requires
  decisions about whether to filter `socket(2)` family/type or to
  filter at userspace via the existing fetch wrapper instead
- Permissive vs strict default needs operator product input

## What the existing fork ships against the same threat

The classes of attack F was sized to defend against — plugin escapes
to host OS, plugin lateral movement between plugins, plugin network
egress to unintended hosts — are partially addressed by the layers
shipped in this session and prior commits:

- Plugin signing + capability manifest at install (G.1 part 1/3 + 2/3):
  unsigned/tampered plugins refused at install; manifest forms a
  declared baseline that runtime enforcement can consult
- Existing docker sandbox backend (`src/agents/sandbox/docker-backend.ts`)
  for tool exec — covers a large fraction of the "plugin runs `rm -rf`"
  attack class today
- External-content wrap + canary + output firewall: blocks the
  laundering channel an attacker would use to drive a plugin into
  unintended behaviour
- Audit chain (P0.6): per-dispatch forensic trail so a compromised
  plugin's actions are traceable

What is genuinely uncovered today vs a full F shipped:
- Kernel-level isolation between the openclaw Node process and tool exec
- Per-plugin network egress allowlist at the syscall level (today the
  allowlist is documented but not enforced)
- Defense against a malicious *signed first-party* plugin (capability
  manifest constrains future runtime enforcement; F adds the
  unforgeable boundary)

## Decision needed from user

To turn F + #24 into a buildable scope, the user needs to choose:

1. **Linux strategy**: Firecracker as a runtime dependency (operator
   installs) vs vendored binary in the openclaw npm package.
2. **macOS strategy**: ship the Swift helper as part of the openclaw
   package or as a separate optional download.
3. **Pooling**: per-session warm-VM pool vs cold boot per tool exec.
4. **Rollout**: F shipped behind `gateway.sandbox.backend = "microvm"`
   default-off, or gated by a separate flag, or default-on once
   stable?
5. **Seccomp surface**: strict syscall allowlist (refuse unknown
   syscalls) vs permissive (block known-dangerous list only)?

Once these are answered, F is a 3–6 week implementation effort with
its own milestone plan, CI work, and operator docs. It is the largest
remaining piece of the security blueprint and deserves a dedicated
scoping conversation before any code lands.

## Mitigations until F lands

- Document the gap in the fork SECURITY.md triage rubric (already done
  in commit `docs(security): fork policy override declaring prompt
  injection in-scope`). Reports of plugin escape to host OS are
  in-scope but the structural defense is acknowledged as future work.
- The docker sandbox backend continues to be the recommended exec
  isolation for security-sensitive deployments.
- Plugin capability manifest verification at install (G.1 part 2/3)
  ensures any future runtime enforcement gate can rely on a signed
  declared surface.

**Recommended next step:** schedule a focused conversation on the five
decisions above; treat F as a separate milestone with its own spec doc
and timeline once the decisions are made.
