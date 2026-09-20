#!/usr/bin/env bash
#
# Distro matrix validation (docs/distro-matrix.md).
#
# Runs the node agent inside each certified test image and asserts what it
# reports. The point is to catch, on every push, the two ways this file could
# start lying:
#
#   1. the agent stops working on a distribution we claim to support, and
#   2. the agent starts claiming service operations it cannot perform on a host
#      without systemd -- a green "all good" that would reach an operator.
#
# Containers do not run systemd as PID 1, so this suite validates the NON-systemd
# path. Certifying the systemd path needs a real host; see the limits section in
# docs/distro-matrix.md rather than treating a pass here as that claim.
#
# Usage:  ./scripts/distro-matrix.sh [--arch amd64|arm64]
# Exit:   0 when every row passed, 1 when any row failed.

set -uo pipefail

# Git Bash on Windows rewrites arguments that begin with "/" into Windows paths
# ("/bin/sh" becomes "C:/Program Files/Git/usr/bin/sh"), which breaks the
# container entrypoint. These are the documented opt-outs; on Linux they are
# ordinary, inert environment variables.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

ARCH="amd64"
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Git Bash reports POSIX-style paths (/f/...) that Docker on Windows cannot
# resolve for a bind mount; cygpath converts to the native form. No-op on Linux,
# where cygpath does not exist.
if command -v cygpath >/dev/null 2>&1; then
  REPO_ROOT="$(cygpath -m "$REPO_ROOT")"
fi
cd "$REPO_ROOT"

# The matrix, as "<family> <version> <image@digest>".
#
# The digest is part of the entry rather than resolved at run time: the
# certification in docs/distro-matrix.md is evidence about THIS image, and
# silently following a tag would attach that evidence to whatever the tag later
# points at.
ROWS=(
  "ubuntu 24.04 ubuntu:24.04@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4"
  "debian 12 debian:12-slim@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b"
  "almalinux 9 almalinux:9-minimal@sha256:d5043630f58d8b1d4a50ffa8f0b245c577425599c8ed595a94deeb978ce484c4"
  "rocky 9 rockylinux:9-minimal@sha256:197b1569a8e5d46de75412cfd80b88a437d25bb2a5338dc82d5421d835245ec7"
  "fedora 42 fedora:42@sha256:7c63468daf71fdc5bda3699cd483b169bb995b5137265d5ffe8f04e2ce87fbb8"
)

# statusOf prints the status of one check from a doctor report.
#
# The report is indented JSON (doctor.Report.JSON uses MarshalIndent, so a human
# can read it) and Check's fields are declared name, status, detail, evidence, so
# the status line always follows the name line. Matching on the key rather than on
# a fixed indent is deliberate: an indent anchor is a guess about a serializer's
# formatting, and the guess fails silently by reporting nothing.
#
# This is a grep rather than a JSON parser because the script must run on a bare
# runner with no jq or python. That is a real constraint on the shape of the
# report, and it is why the report's own field order is load-bearing here.
statusOf() {
  local json="$1" name="$2"
  printf '%s\n' "$json" \
    | grep -A1 "\"name\": \"${name}\"," \
    | grep -m1 '"status":' \
    | sed 's/.*"status": "\([a-z]*\)".*/\1/'
}

# fieldOf prints a top-level evidence value from the report.
#
# The evidence object is the only place these keys appear, so matching the key
# alone is unambiguous. os_family and os_version are strings; nothing else would
# be meaningful to compare against a matrix row.
fieldOf() {
  local json="$1" key="$2"
  printf '%s\n' "$json" \
    | grep -m1 "\"${key}\":" \
    | sed 's/.*: "\([^"]*\)".*/\1/'
}

# runRow executes the assertions for one image.
#
# The assertions are about what the agent CLAIMS rather than about whether it
# merely starts: a binary that runs and then reports no distribution, or claims
# service operations it cannot perform, is worse than one that fails loudly,
# because the first two are indistinguishable from success in a dashboard.
runRow() {
  local family="$1" version="$2" image="$3"
  local label="${family} ${version}"
  local failures=0

  # --rm so a failed run cannot leave a container behind. The agent is mounted
  # read-only; the image is pulled by digest, so this is reproducible.
  #
  # doctor exits non-zero when any check FAILED, and on a container that has
  # never enrolled that is the CORRECT report (state-directory and node-identity
  # fail by design). So its exit code is not the verdict here -- the assertions
  # below read the report instead. Only a binary that cannot execute at all is a
  # run failure, and that is the one case mapped to a distinct code.
  local out
  out="$(docker run --rm --platform "linux/${ARCH}" \
    -v "${REPO_ROOT}/${AGENT}:/usr/local/bin/jawaker-node-agent:ro" \
    --entrypoint /bin/sh "${image}" -c '
      /usr/local/bin/jawaker-node-agent version || exit 9
      /usr/local/bin/jawaker-node-agent doctor --json --skip-connectivity
      exit 0
    ' 2>&1)"
  local rc=$?

  if [ $rc -eq 9 ]; then
    echo "FAIL ${label}: the agent binary did not execute in this image"
    printf '%s\n' "$out" | sed 's/^/     /'
    return 1
  fi
  if [ $rc -ne 0 ]; then
    # Anything else is docker itself: a missing image, a refused daemon, a pull
    # failure. Reported as such rather than as an agent defect.
    echo "FAIL ${label}: the container could not be run (exit ${rc})"
    printf '%s\n' "$out" | sed 's/^/     /'
    return 1
  fi

  # The version line precedes the JSON; keep from the first brace.
  local json
  json="$(printf '%s\n' "$out" | sed -n '/^{/,$p')"
  if ! printf '%s' "$json" | grep -q '"component": "node-agent"'; then
    echo "FAIL ${label}: doctor emitted no parseable report"
    printf '%s\n' "$out" | sed 's/^/     /'
    return 1
  fi

  # 1. The report must name the distribution the container is actually running.
  #    Matching the row is what makes this a matrix check rather than a smoke
  #    test: an agent reporting a constant would pass "did it run" and fail here.
  local detected
  detected="$(fieldOf "$json" os_family)"
  if [ "$detected" != "$family" ]; then
    echo "FAIL ${label}: host-identity reported os_family='${detected}', expected '${family}'"
    failures=$((failures + 1))
  fi

  # The version prefix is a weaker assertion on purpose: distributions spell it
  # differently ("24.04" vs "24.04.1", "12" vs "12.11"), so requiring equality
  # would fail on a legitimate point release. The prefix still catches a report
  # naming the wrong release line.
  local detectedVersion
  detectedVersion="$(fieldOf "$json" os_version)"
  case "$detectedVersion" in
    "${version}"*) ;;
    *)
      echo "FAIL ${label}: host-identity reported os_version='${detectedVersion}', expected '${version}*'"
      failures=$((failures + 1))
      ;;
  esac

  # 2. host-identity must be ok. A warn means the agent could not identify the
  #    host, which is the failure this row exists to detect.
  if [ "$(statusOf "$json" host-identity)" != "ok" ]; then
    echo "FAIL ${label}: host-identity status is not ok"
    failures=$((failures + 1))
  fi

  # 3. The inventory inputs must be present: runtime-files is the check that
  #    reads /etc/os-release.
  if [ "$(statusOf "$json" runtime-files)" != "ok" ]; then
    echo "FAIL ${label}: runtime-files status is not ok"
    failures=$((failures + 1))
  fi

  # 4. No systemd in a container, so service operations MUST be reported as
  #    degraded. If this ever reads "ok", the agent is claiming a capability it
  #    cannot deliver -- exactly the false status this suite exists to prevent.
  if [ "$(statusOf "$json" operation-support)" = "ok" ]; then
    echo "FAIL ${label}: operation-support reported ok inside a container without systemd"
    failures=$((failures + 1))
  fi

  # 5. Nothing enrolled this container, so an ok identity would mean the agent
  #    invented one.
  if [ "$(statusOf "$json" node-identity)" = "ok" ]; then
    echo "FAIL ${label}: node-identity reported ok on a host that never enrolled"
    failures=$((failures + 1))
  fi

  if [ "$failures" -eq 0 ]; then
    echo "PASS ${label} (${image%%@*}, os ${detected} ${detectedVersion})"
    return 0
  fi
  printf '%s\n' "$json" | head -c 2000 | sed 's/^/     /'
  echo
  return 1
}

# Build once. CGO_ENABLED=0 makes this a static binary with no libc to match,
# which is what lets one build run on every image below.
AGENT="bin/jawaker-node-agent-linux-${ARCH}"
echo "== building ${AGENT}"
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" go build -trimpath \
  -ldflags "-s -w -X github.com/bukansembarangkong/jawaker-panel/internal/version.Version=matrix-test" \
  -o "${AGENT}" ./cmd/node-agent || { echo "build failed"; exit 1; }

echo "== validating ${#ROWS[@]} rows for linux/${ARCH}"
FAILED=0
for row in "${ROWS[@]}"; do
  # Word-splitting is the intent: each row is three positional fields.
  # shellcheck disable=SC2086
  set -- $row
  runRow "$1" "$2" "$3" || FAILED=$((FAILED + 1))
done

echo
if [ "$FAILED" -ne 0 ]; then
  echo "distro matrix: ${FAILED} row(s) failed"
  exit 1
fi
echo "distro matrix: all rows passed"
