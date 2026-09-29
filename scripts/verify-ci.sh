#!/usr/bin/env bash
#
# Local CI-equivalent verification for web2-ish-self-custody.
#
# Mirrors .github/workflows/ci.yml (the single `verify` job) on this machine, so
# a green signal does not depend on GitHub Actions being available. CI runs:
#
#   setup-node (matrix: node 22, 24)
#   setup-python 3.12
#   python -m pip install --only-binary=:all: --require-hashes -r scripts/requirements-vector-verifier-ci.txt
#   npm ci
#   npm run verify        # = typecheck && test && verify:vectors:python && build
#
# This script runs the four steps behind `npm run verify` individually, so each
# reports its own PASS/FAIL instead of the whole chain stopping at the first
# `&&`. Running every gate is otherwise identical to what CI executes.
#
# NOT covered locally — these print SKIP with a reason, never silent omission:
#
#   * The Node version matrix. Only the Node running this script is exercised.
#     The other matrix arm needs a second runtime (nvm/fnm/volta) or a CI runner.
#   * CI's hash-pinned pip install. scripts/requirements-vector-verifier-ci.txt
#     pins linux/x86_64 CPython 3.12 wheels by sha256, so it cannot resolve on
#     macOS or on arm64 at all. In its place this script checks offline that
#     every requirement is `==` pinned with a sha256 hash, and runs the vector
#     gate against whatever `cryptography` is already importable (skipping that
#     gate, loudly, if there is none). Pass --pip on a matching Linux host to
#     run CI's exact command in a throwaway venv.
#   * The real-PostgreSQL server suites. vitest skips them unless
#     W2SC_TEST_DATABASE_URL is set, and CI does not set it either. Pass --pg
#     with that variable exported to run them.
#
# Usage:
#   scripts/verify-ci.sh          # every gate that can run locally
#   scripts/verify-ci.sh --pip    # also run CI's exact hash-pinned pip install
#   scripts/verify-ci.sh --pg     # also run the PostgreSQL integration suites
#
# Each gate prints PASS/FAIL; the exit code is the number of failed gates.

set -u
cd "$(dirname "$0")/.."

want_pip=false
want_pg=false
for arg in "$@"; do
  case "$arg" in
    --pip) want_pip=true ;;
    --pg) want_pg=true ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [ "$want_pg" = true ] && [ -z "${W2SC_TEST_DATABASE_URL:-}" ]; then
  echo "--pg requires W2SC_TEST_DATABASE_URL to be exported" >&2
  exit 2
fi

if [ ! -d node_modules ]; then
  echo "node_modules is missing. Install dependencies first (npm ci, or npm" >&2
  echo "install if the 'npm ci' gate below reports the lockfile is out of sync)." >&2
  exit 2
fi

log="$(mktemp -t w2sc-verify-ci)"
trap 'rm -f "$log"' EXIT

failures=0
run() {
  local name="$1"; shift
  echo "── ${name}"
  if "$@" >"$log" 2>&1; then
    echo "   PASS: ${name}"
  else
    echo "   FAIL: ${name}"
    tail -30 "$log" | sed 's/^/     /'
    failures=$((failures + 1))
  fi
}

skip() {
  echo "── $1"
  echo "   SKIP: $2"
}

# --- setup-node: is this runtime one CI actually tests? ---------------------
# The matrix is read out of the workflow so this cannot drift away from CI.
ci_node_matrix() {
  sed -n 's/.*node-version: *\[\([^]]*\)\].*/\1/p' .github/workflows/ci.yml \
    | head -1 | tr -d ' ' | tr ',' ' '
}

check_node_matrix() {
  local matrix major
  matrix="$(ci_node_matrix)"
  if [ -z "$matrix" ]; then
    echo "could not read the node-version matrix from .github/workflows/ci.yml"
    return 1
  fi
  major="$(node -p 'process.versions.node.split(".")[0]')" || return 1
  for version in $matrix; do
    if [ "$version" = "$major" ]; then
      return 0
    fi
  done
  echo "local Node ${major} ($(node -v)) is not in CI's matrix: ${matrix}"
  return 1
}

node_matrix="$(ci_node_matrix)"
local_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo '?')"
echo "CI node matrix: [${node_matrix}]  |  local: $(node -v 2>/dev/null || echo 'node not found')"
run "node runtime is in CI's matrix" check_node_matrix
for version in $node_matrix; do
  if [ "$version" != "$local_major" ]; then
    skip "matrix arm: node ${version}" "no node ${version} runtime here; needs nvm/fnm/volta or a CI runner"
  fi
done

# --- setup-python + hash-pinned pip install --------------------------------
# Offline stand-in for what CI's `--require-hashes` enforces: every requirement
# must be == pinned and carry a sha256 hash.
check_requirements_pinned() {
  local file="scripts/requirements-vector-verifier-ci.txt"
  if [ ! -f "$file" ]; then
    echo "missing ${file}"
    return 1
  fi
  awk '
    function check() {
      if (buf !~ /[^ \t]/) return
      if (buf !~ /[A-Za-z0-9._-]+==[^ \t]+/) {
        printf("not version-pinned:%s\n", buf); bad = 1
      } else if (buf !~ /--hash=sha256:[0-9a-f][0-9a-f]*/) {
        printf("no sha256 hash:%s\n", buf); bad = 1
      } else {
        pinned++
      }
    }
    { sub(/#.*/, "")
      continued = ($0 ~ /\\[ \t]*$/)
      sub(/\\[ \t]*$/, "")
      buf = buf " " $0
      if (!continued) { check(); buf = "" } }
    END { check()
          if (!bad && pinned == 0) { print "no requirements found"; bad = 1 }
          if (!bad) printf("%d requirement(s), all pinned with a sha256 hash\n", pinned)
          exit bad }
  ' "$file"
}

run "vector verifier requirements are hash-pinned" check_requirements_pinned

if [ "$want_pip" = true ]; then
  run "pip install --require-hashes (CI's exact command)" bash -c '
    venv="$(mktemp -d)/venv"
    python3 -m venv "$venv" &&
    "$venv/bin/python" -m pip install \
      --disable-pip-version-check \
      --only-binary=:all: \
      --require-hashes \
      -r scripts/requirements-vector-verifier-ci.txt'
else
  skip "pip install --require-hashes" \
    "hashes pin linux/x86_64 CPython 3.12 wheels; pass --pip on a matching host"
fi

# --- npm ci ----------------------------------------------------------------
# --dry-run resolves the ideal tree from the lockfile without touching
# node_modules or the network, and still fails the way CI's `npm ci` fails when
# package.json and package-lock.json have drifted apart.
check_npm_ci() {
  local out status
  out="$(npm ci --dry-run --no-audit --no-fund --ignore-scripts 2>&1)"
  status=$?
  if [ "$status" -ne 0 ]; then
    # npm appends its entire --help text after a EUSAGE lockfile error. Keep
    # only the diagnosis above that banner so the real reason is visible.
    printf '%s\n' "$out" | awk '/^npm error Clean install a project/ { exit } { print }'
  fi
  return "$status"
}

run "npm ci (lockfile in sync with package.json)" check_npm_ci

# --- npm run verify, one gate per step -------------------------------------
run "typecheck"   npm run --silent typecheck
run "unit tests"  npm test
if python3 -c 'import cryptography' >/dev/null 2>&1; then
  run "python vectors" npm run --silent verify:vectors:python
else
  skip "python vectors" \
    "python3 with the 'cryptography' module is not available on this machine"
fi
run "build"       npm run --silent build

# --- optional: real PostgreSQL ---------------------------------------------
if [ "$want_pg" = true ]; then
  run "server integration tests (real PostgreSQL)" npx vitest run test/server
else
  skip "server integration tests (real PostgreSQL)" \
    "W2SC_TEST_DATABASE_URL not set; vitest skips them, as CI does. Use --pg to run"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "ALL LOCAL CI GATES PASSED"
else
  echo "${failures} GATE(S) FAILED"
fi
exit "$failures"
