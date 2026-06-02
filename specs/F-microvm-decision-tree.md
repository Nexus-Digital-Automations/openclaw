# F microvm sandbox — decision tree

**Status:** five user decisions block the start of F.1/F.2/G.1#24
implementation. The existing escalation doc at
`specs/F-microvm-sandbox-escalation.md` enumerates the open questions
in prose. This spec restructures them as a fill-in decision tree so the
user can resolve each axis without re-reading the escalation. Once the
five blocks below are filled in, F becomes its own multi-week milestone
with a dedicated implementation plan.

## How to use

Edit this file in place. Replace each `[ ]` with `[x]` next to the
chosen option. Add brief rationale per pick in the **Operator notes**
slot so future readers see why one path was chosen over another. Once
all five decisions are recorded, the operator hands this off as the
input brief to the F implementation plan.

## Decision 1 — Linux runtime sourcing

How does openclaw obtain the `firecracker` binary on Linux hosts?

- [ ] **A. Operator-installed runtime dependency.** The operator
      installs Firecracker via their package manager / curl-binary; the
      openclaw npm package documents the requirement and `openclaw
    doctor --fix` checks for it. Pros: smaller npm tarball, version
      pinning is the operator's job. Cons: more onboarding friction;
      every host needs a working Firecracker before microvm sandbox is
      usable.
- [ ] **B. Vendored pinned binary in the openclaw npm package.** A
      per-arch `firecracker-${arch}` binary ships in
      `extensions/sandbox-microvm/bin/`. Pros: zero-config for the
      operator. Cons: large tarball; we own version + supply-chain risk
      for the binary.

**Operator notes:** _replace this line with rationale_

## Decision 2 — macOS runtime sourcing

How does openclaw obtain the Swift helper binary on macOS hosts?

- [ ] **A. Bundled with the openclaw package.** The signed
      `OpenclawMicrovmHelper.app` ships in the same tarball that ships
      the Mac gateway. Pros: zero-config; we control the signing
      identity. Cons: tarball grows; we own Apple-side signing CI work.
- [ ] **B. Separate optional download.** `openclaw doctor --fix`
      offers to download the helper from a verified release artifact
      when the operator opts into microvm mode. Pros: smaller default
      tarball. Cons: extra download step; supply-chain check shifted to
      download-time signature verification.

**Operator notes:** _replace this line with rationale_

## Decision 3 — VM pooling strategy

How does openclaw amortize Firecracker / Virtualization.framework boot
cost across tool calls?

- [ ] **A. Per-session warm VM pool.** A small number (e.g. 2-3) of
      pre-warmed VMs per active session. Pros: tool-exec latency stays
      in the docker-backend class (~10ms reuse vs ~125ms cold). Cons:
      memory cost scales with active sessions; pool lifecycle is its
      own state machine.
- [ ] **B. Cold boot per tool exec.** Spin up a fresh VM for every
      tool call, tear down on completion. Pros: no pool state to
      manage; memory footprint is bounded by concurrency. Cons:
      ~125ms per tool call latency is user-noticeable.

**Operator notes:** _replace this line with rationale_

## Decision 4 — Rollout default

What's the default state of microvm sandbox once F lands?

- [ ] **A. `gateway.sandbox.backend = "microvm"` default-off.** Operator
      opts in via config. Pros: minimal risk during stabilization.
      Cons: low adoption; the security improvement is shelfware unless
      the operator knows to flip it.
- [ ] **B. Gated behind a separate `--experimental-microvm` flag.** No
      config change; users explicitly run with the flag during the
      early rollout. Pros: clearer expectation that this is preview.
      Cons: yet another flag.
- [ ] **C. Default-on once stable.** After a stabilization window
      (e.g. 2-3 minor versions of beta), microvm becomes the default
      backend. Pros: maximum security coverage. Cons: any latency
      regression hits everyone.

**Operator notes:** _replace this line with rationale_

## Decision 5 — Seccomp profile shape

How strict is the syscall allowlist inside the microvm guest?

- [ ] **A. Strict allowlist.** The guest init filter refuses every
      syscall not explicitly allowed by the plugin's
      `PluginCapabilities` manifest. Pros: minimal kernel attack
      surface. Cons: maintenance burden; any new bundled-plugin feature
      that needs a new syscall triggers a manifest + seccomp profile
      update.
- [ ] **B. Permissive deny-list.** The guest filter blocks a known
      list of dangerous syscalls (`ptrace`, `bpf`, `kexec_load`, etc.)
      but allows the rest. Pros: lower churn; lower risk of breaking
      legitimate plugins. Cons: any new dangerous syscall added to the
      kernel is a default-allow until we explicitly catch it.

**Operator notes:** _replace this line with rationale_

## After decisions land

Once all five are picked, the next deliverable is a focused F-1
implementation plan covering:

1. Linux `microvm-backend.ts` skeleton with the chosen runtime sourcing
2. macOS Swift helper skeleton with the chosen distribution shape
3. Pool / cold-boot lifecycle implementation per Decision 3
4. Sandbox config + telemetry per Decision 4
5. Seccomp profile generator that reads `PluginCapabilities` per
   Decision 5

Estimated effort post-decisions: 3-6 weeks of focused infrastructure
work, plus CI/release-pipeline integration.

## References

- `specs/F-microvm-sandbox-escalation.md` — original escalation doc
- `specs/security-blueprint-full.md` — Track F + G.1 source scope
- `src/agents/sandbox/backend.ts` — existing `SandboxBackendHandle`
  contract microvm will implement
- `src/agents/sandbox/docker-backend.ts` — reference implementation of
  the same contract
- `src/plugins/capabilities.ts` — `PluginCapabilities` shape that
  Decision 5's seccomp generator reads from
