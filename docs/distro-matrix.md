# JAWAKER — supported distribution matrix

This file is the **single source of truth** for which distribution and version a
JAWAKER node runs on, and what evidence that claim rests on. Status is a claim
about evidence, so every row names the test image it was validated against and
the digest that evidence applies to.

> [!IMPORTANT]
> A distribution must never be treated as supported because the node agent
> happened to start on it, and a new release of a distribution does not inherit
> its predecessor's status (TESTING.md §7, PRD.md §7.2). Both rules exist for
> the same reason: the failure mode is an operator being told a machine is
> supported when nobody has tested it.

## Status vocabulary (PRD.md §7.2, TESTING.md §7)

The meanings below are the specification's, not this document's. "Certified" is
deliberately the highest bar: per TESTING.md §7 it requires installation, core
operation, upgrade and recovery scenarios to pass on the exact supported version
family, and per PRD.md §7.3 that also spans package management, firewall,
networking, web engines, runtimes, databases, containers, backup/restore and
rollback. Nothing in Phase 2 reaches it, which is why no row below is Certified.

| Status | Meaning |
| --- | --- |
| **Certified** | Install + core operation + upgrade + recovery passed on this exact version family (TESTING.md §7, PRD.md §7.3). |
| **Testing** | Under active validation; usable in development, not in production. |
| **Experimental** | The agent is expected to work but has not been run through the suite. |
| **Deprecated** | Previously certified; a replacement exists and this pair is on its way out. |
| **Unsupported** | Not validated, or known not to work. |

## Phase 2 matrix — node agent

Phase 2 validates the **node agent**: enrollment, mTLS, heartbeat, capability
and OS inventory, typed service inspection/restart, and `doctor`. It does **not**
cover installation, package management, upgrade, recovery, Nginx, PHP, databases
or backup — PRD.md §7.3 requires all of those before the word "Certified" may be
used, and those arrive with their own phases. So the strongest status any row
here can hold is **Testing**. A green run is evidence toward Certified, not a
shorter route to it: it covers part of "core operation" and none of the rest.

| Family | Version | Status | Test image | amd64 digest |
| --- | --- | --- | --- | --- |
| Ubuntu | 24.04 LTS | Testing | `ubuntu:24.04` | `sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4` |
| Debian | 12 (bookworm) | Testing | `debian:12-slim` | `sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b` |
| AlmaLinux | 9 | Testing | `almalinux:9-minimal` | `sha256:d5043630f58d8b1d4a50ffa8f0b245c577425599c8ed595a94deeb978ce484c4` |
| Rocky Linux | 9 | Testing | `rockylinux:9-minimal` | `sha256:197b1569a8e5d46de75412cfd80b88a437d25bb2a5338dc82d5421d835245ec7` |
| Fedora Server | 42 | Testing | `fedora:42` | `sha256:7c63468daf71fdc5bda3699cd483b169bb995b5137265d5ffe8f04e2ce87fbb8` |

These are the families PRD.md §7.1 names, and the suite passes on every digest
above. Containers cannot run systemd, so service management is not exercised
anywhere in it.

The suite has passed on these digests, reporting the versions below — note that they are not what a human would have written in the table, which is why the version assertion matches a prefix:

| Image | Reported `os_family` | Reported `os_version` |
| --- | --- | --- |
| `ubuntu:24.04` | `ubuntu` | `24.04` |
| `debian:12-slim` | `debian` | `12` |
| `almalinux:9-minimal` | `almalinux` | `9.8` |
| `rockylinux:9-minimal` | `rocky` | `9.3` |
| `fedora:42` | `fedora` | `42` |

AlmaLinux and Rocky report a point release, and Rocky reports the family as `rocky` rather than `rockylinux`. Both are facts about the images, not defects — and both would have failed an assertion demanding equality with the matrix row, which is why the check requires only that the report starts with the row's version.

### Why digests, not tags

A tag is a moving pointer: `ubuntu:24.04` will silently become a different image
the next time it is rebuilt, and a certification that names only the tag cannot
say what it validated. The digest is what the evidence attaches to. When a
digest changes, the row is re-run — not assumed still good.

### Why the images are minimal/slim variants

The agent's dependencies are the kernel, `/etc/os-release`, `/proc`, and
systemd. A minimal image is therefore a *more* honest test target than a full
one: it fails loudly if the agent ever grows a dependency it should not have.
Note that systemd is absent inside a container, so these runs validate the
**non-systemd** path (capabilities reported, service operations refused) — see
the limits below.

## Running the suite

Locally, with a Docker daemon available:

```sh
./scripts/distro-matrix.sh
```

In CI, the `distro` job in `.github/workflows/ci.yml` runs the same script on
every push and pull request. It builds the agent for the target architecture,
then for each row: starts the image, installs the binary, and asserts that
`doctor --json` reports the distribution it is running on and does not claim
service operations it cannot perform.

## What the suite asserts, and what it does not

Asserted per row:

1. `jawaker-node-agent version` runs and reports the injected version — a binary
   that cannot execute on the image fails here rather than later.
2. `doctor --json` completes and emits parseable JSON.
3. `host-identity` is `ok`, and its `os_family` and `os_version` match the matrix
   row — so a row cannot pass on an image that reports a different distribution.
4. `runtime-files` is `ok`, so the inventory inputs the agent reads are present.
5. `operation-support` is **not** `ok`, because the image has no systemd and a
   green tick here would imply service management works.
6. `node-identity` is **not** `ok`, because nothing has enrolled this host —
   reporting identity that does not exist is the failure this catches.

Not asserted, and deliberately not claimed by "Testing":

- **systemd service operations.** Containers do not run systemd as PID 1, so
  inspect/restart cannot be exercised here. Covering them on a real systemd host
  is necessary for Certified but not sufficient — TESTING.md §7 also requires
  install, upgrade and recovery. Until all of that passes, the agent's own
  `CapabilityUnsupported` report is what tells an operator the truth.
- **Enrollment against a live controller.** Covered by the integration suite
  (`internal/controller/nodes_integration_test.go`), not by this matrix.
- **Install, upgrade, uninstall, firewall, Nginx, PHP, databases, backup,
  rollback.** Out of Phase 2 scope (PRD.md §7.3).
