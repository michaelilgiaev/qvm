#!/usr/bin/env bash
#
# qvm -- test entry point.
#
# `bash tests.sh` is the ONE command. It is self-bootstrapping: it creates the
# venv if it is missing, installs requirements.txt into it, and runs pytest.
# No global Python packages are touched -- everything lives in ./cache/venv (which
# is gitignored). Re-running is cheap: the venv and its installed packages persist,
# and pip is skipped entirely when requirements.txt has not changed.
#
# The tests here are PURE unit tests. They never build an ISO, never call
# pacman/makepkg/mkarchiso, never touch the network, never use sudo or Docker.
# They exercise the deterministic Python logic (the configuration-file emitters, the
# package list handling, path building, the specification pipeline's transforms) -- the
# exact code where a silent regression turns into whack-a-mole. If a test needs
# a real build tool, it does not belong here.
#
# --- OUTPUT MODES ------------------------------------------------------------
# Exactly one of three verbosity modes selects what the TERMINAL shows, chosen by
# a flag CONSUMED here (never forwarded to pytest). All three are COLORED and all
# three fit the terminal width (nothing ever overflows, even a 300-digit param id).
#
#   (no flag)   MIXED  -- dots grouped per file. Each line is a general
#                         category (the test file's path) followed by one dot
#                         per test in it: `tests/test_paths.py ..........`.
#                         Colored (green dot pass, red F/E fail). The default.
#   -q, --quiet QUIET  -- green dots. Just the dots, nothing else to read.
#   -l, --loud  LOUD   -- an eyesore. Loudest pytest has: -vv, one bright
#                         colored line per test, full long tracebacks (failures
#                         reported; a clean run has no trailing PASSED wall).
#
# -q and -l are mutually exclusive; passing both is a hard error.
#
# LOGS: independent of the mode on screen, EVERY run writes all three views to
# logs/ (color-stripped): tests.log (mixed), tests-loud.log (loud), tests-quiet.log
# (quiet). Each view is produced by its OWN native pytest run: the TERMINAL run (the
# selected mode) writes its own log as it prints, and the OTHER TWO modes each run
# in a throwaway COPY of the repo, concurrently, feeding their logs. Native-per-mode
# means pytest emits exactly the right layout for each view, so no `-vv` artifact
# (wrapped skip reasons, digit walls) ever leaks into the leaner mixed/quiet views.
# A small awk only fits lines to the terminal WIDTH; it never reconstructs dots.
#
# --- TEST MODES (network + root; both OFF by default) ------------------------
# Two PERSISTED booleans in tests/test_modes.conf select which privileged tiers
# actually run. Both default OFF, so a plain `bash tests.sh` is green with no
# connectivity and no sudo. The conf is LOCAL per-machine state: it is gitignored,
# not committed. tests.sh CREATES it (both false) on first run if it is missing and
# otherwise leaves it alone, so a fresh clone starts both-off and each machine keeps
# its own toggles.
#
#   network -- a few tests reach a REAL external host (marked `network`). OFFLINE
#              (default) SKIPS them, so a plain run never hangs on a DNS lookup.
#              ONLINE runs them.
#   root    -- tests that need UID 0 (marked `root`; the two calamares btrfs
#              loop-mount desparse tests). USER (default) SKIPS them. ROOT enables
#              the tier -- and because these tests do nothing useful without UID 0,
#              a ROOT-mode `bash tests.sh` run WITHOUT sudo now STOPS and tells you
#              to re-run under sudo, instead of quietly skipping what you enabled.
#              (Under sudo they run; selecting the tier does not otherwise force root.)
#
# The toggles are flipped WITHOUT running the suite (they rewrite
# tests/test_modes.conf and exit immediately -- no venv build, no pytest, no sudo
# demand -- flipping the switch is always allowed):
#   bash tests.sh --offline / --online   # flip `network`; does NOT run the suite
#   bash tests.sh --user    / --root     # flip `root`;    does NOT run the suite
# Passing both halves of a pair (e.g. --online --offline) is a hard error. Flip both
# at once:  bash tests.sh --online --root
# Override either for a single run without editing the file (env wins over the file):
#   QVM_TESTS_NETWORK=online QVM_TESTS_ROOT=true bash tests.sh
# These toggles are INDEPENDENT of the output-verbosity flags (-q/--quiet, -l/--loud).
#
# --- HELP --------------------------------------------------------------------
#   bash tests.sh --help  (or -h)   # print usage for every flag and exit
#
# --- PASS-THROUGH ------------------------------------------------------------
# Any OTHER arguments are passed straight through to pytest (only the mode/output
# flags above are stripped), e.g.:
#   bash tests.sh -k pacman                # run only tests matching "pacman"
#   bash tests.sh tests/test_paths.py      # run one file
#   bash tests.sh -q -k pacman             # green dots, only "pacman" tests
#   bash tests.sh -l tests/test_emit.py    # eyesore, one file

set -o errexit
set -o nounset
set -o pipefail

REPODIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPODIR"

VENV="$REPODIR/cache/venv"
PY="$VENV/bin/python"
REQ="$REPODIR/requirements.txt"
STAMP="$VENV/.requirements.installed"
LOGDIR="$REPODIR/logs"
# Every run writes ALL THREE views to logs/, no matter which mode the terminal
# shows: tests.log (mixed / default), tests-loud.log (loud), tests-quiet.log
# (quiet). The terminal shows only the selected mode; logs/ always gets all three
# (the shown mode from the terminal run, the other two from isolated copies).
LOG_MIXED="$LOGDIR/tests.log"
LOG_LOUD="$LOGDIR/tests-loud.log"
LOG_QUIET="$LOGDIR/tests-quiet.log"

# --- Test modes (network + root; both OFF by default) -----------------------
# Two PERSISTED booleans in tests/test_modes.conf select the privileged tiers. The file is
# LOCAL per-machine state -- it is gitignored, NOT committed. tests.sh CREATES it (both
# `false`) on first run if it is missing, and otherwise leaves it untouched on a normal run,
# so a fresh clone starts with both tiers OFF (no network hang, no sudo demand) and each
# machine keeps its own toggles. conftest.py reads the file; QVM_TESTS_NETWORK /
# QVM_TESTS_ROOT override it for one run; we export both below so the terminal run and the
# two isolated log-copy runs all agree with the file. See tests/_testmodes.py for the parser
# and precedence rules.
MODESCONF="$REPODIR/tests/test_modes.conf"

# Ensure the local conf exists before ANY read of it (the toggle writer, conf_bool, the
# env-export, and the root-sudo guard below all read it). If it is missing -- a fresh clone,
# or a machine where it was never created -- write the safe both-OFF default. If it already
# exists we do NOT touch it: it is the user's local state and only an explicit toggle flag
# (handled below) may rewrite it. This is idempotent and side-effect free on every run after
# the first, and it means every code path downstream can assume the file is present.
if [ ! -f "$MODESCONF" ]; then
    mkdir -p "$(dirname "$MODESCONF")"
    printf 'network = false\nroot = false\n' > "$MODESCONF"
fi

# conf_bool <key> -- read one boolean from tests/test_modes.conf, echoing `true`/`false`. This is
# the ONE parser used by both the toggle writer and the env-export below, and it is kept faithful to
# tests/_testmodes.py's Python parser so `bash tests.sh` and a bare `pytest` never disagree on the
# same file:
#   * value is TRIM-only (leading/trailing ASCII whitespace), matching Python's str.strip() -- we do
#     NOT strip interior spaces, so a mangled `t rue` is UNRECOGNIZED and falls closed (false), not
#     silently coerced to true.
#   * a POSITIVE ALLOWLIST gate: after trim+fold, any value containing a character outside [a-z0-9]
#     is rejected as false BEFORE token-matching. Every real token (true/false/1/0/yes/no/on/off/
#     online/offline) is pure [a-z0-9], so nothing legitimate is lost -- but this makes junk with
#     exotic bytes (a stray NBSP U+00A0, a Unicode line separator U+2028, an interior form-feed)
#     fail CLOSED here, converging on Python (whose ASCII-only strip already leaves such values
#     unrecognized). Gating on an allowlist -- not a blocklist of bad chars -- is why this covers the
#     whole class rather than a handful of enumerated characters.
#   * true tokens: true/1/yes/on. false tokens: false/0/no/off. Anything else -> false (fail closed).
#   * the legacy words `online`/`offline` are accepted ONLY for the `network` key (online=true,
#     offline=false) -- they are meaningless for `root`, which is why _network_token() in Python
#     applies them for network alone. Accepting `online` for `root` here would diverge from Python.
# Missing file / missing key -> false. Never fails under errexit/nounset (all reads are guarded).
# (One pathological input stays engine-specific and is deliberately not chased: a NUL byte anywhere
# in the file makes GNU grep report "binary file matches" and skip the line -> false here, while
# Python reads the surrounding lines. A NUL cannot occur in this two-line boolean file in practice,
# and both readings are SAFE -- the committed default is false -- so forcing byte-identical NUL
# handling between grep and CPython is not worth a bespoke pure-bash line reader.)
conf_bool() {                              # conf_bool <key> -> echoes true|false
    local key="$1" line val
    [ -f "$MODESCONF" ] || { echo false; return; }
    line="$(grep -iE "^[[:space:]]*$key[[:space:]]*=" "$MODESCONF" | tail -n1 || true)"
    val="${line#*=}"                        # everything after the first '='
    val="${val#"${val%%[![:space:]]*}"}"    # trim leading whitespace (edges only, like str.strip)
    val="${val%"${val##*[![:space:]]}"}"    # trim trailing whitespace
    val="$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')"   # case-fold; interior spaces PRESERVED
    case "$val" in *[!a-z0-9]*) echo false; return ;; esac     # allowlist gate: junk -> fail closed
    if [ "$key" = network ]; then
        case "$val" in online) echo true; return ;; offline) echo false; return ;; esac
    fi
    case "$val" in
        true|1|yes|on) echo true ;;
        *)             echo false ;;
    esac
}

# ENV token parsers -- resolve an ENV OVERRIDE value to true|false|unknown, applying the SAME
# normalize _testmodes.py's _as_bool/_network_token use (ASCII-trim both ends + case-fold), so the
# early `--status` report and the root-sudo guard below agree with what a real run resolves. `unknown`
# means the env value is unrecognized (empty, whitespace-only, or junk) -- the caller then ABSTAINS to
# the conf file, exactly as Python does (an unrecognized env is None, never a bare false). These read
# ONLY their single argument (never the conf), so they are pure and side-effect free.
#   * root_env_token: the generic boolean tokens only -- `online`/`offline` are meaningless for root
#     (matches _as_bool, which _testmodes.py uses for QVM_TESTS_ROOT).
#   * net_env_token:  additionally accepts the legacy words online=true / offline=false (matches
#     _network_token, used for QVM_TESTS_NETWORK), then falls through to the generic tokens.
root_env_token() {                         # root_env_token <raw> -> true|false|unknown
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"   # ASCII-trim both ends
    v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"            # case-fold
    case "$v" in true|1|yes|on) echo true ;; false|0|no|off) echo false ;; *) echo unknown ;; esac
}
net_env_token() {                          # net_env_token <raw> -> true|false|unknown
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"   # ASCII-trim both ends
    v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"            # case-fold
    case "$v" in online) echo true; return ;; offline) echo false; return ;; esac  # legacy words (network only)
    case "$v" in true|1|yes|on) echo true ;; false|0|no|off) echo false ;; *) echo unknown ;; esac
}

# --help / -h and the four toggle flags (--online/--offline, --user/--root) are handled
# in THIS early pass, BEFORE output-mode parsing / venv bootstrap, so help and toggles
# are instant (no venv build, no pytest -- a toggle rewrites the conf and EXITS). The only
# filesystem touch on this path is the one-time auto-create of the conf just above, which
# writes the both-off default if (and only if) the file is missing -- a no-op on every run
# after the first. Anything else falls through untouched to the normal run below.
#
# usage -- print help covering every flag, then the caller exits 0.
usage() {
    cat <<'EOF'
Usage: bash tests.sh [FLAGS] [PYTEST ARGS...]

The ONE command to run the qvm test suite. Self-bootstrapping: builds ./venv, installs
requirements.txt, runs pytest. Re-running is cheap. All flags below are CONSUMED here (never
forwarded to pytest); everything else passes straight through to pytest.

Output modes (what the TERMINAL shows; logs/ always gets all three views):
  (no flag)        MIXED  -- per-file grouped dots (the default)
  -q, --quiet      QUIET  -- bare green dots
  -l, --loud       LOUD   -- one bright line per test, full tracebacks
  -q and -l are mutually exclusive.

tests/test_modes.conf is LOCAL (gitignored); tests.sh creates it (both false) on first run.

Test-mode toggles (flip a persisted boolean in tests/test_modes.conf and EXIT; no suite run):
  --offline / --online   network tier: skip / run the `network`-marked tests (default: offline)
  --user    / --root     root tier:    skip / enable the `root`-marked tests  (default: user)
  Passing both halves of a pair is an error. Flip both at once, e.g.:  --online --root
  These are INDEPENDENT of -q/-l. Env overrides for one run (env wins over the file):
      QVM_TESTS_NETWORK=online|offline   QVM_TESTS_ROOT=true|false
  With the root tier ENABLED, a plain `bash tests.sh` (no sudo) STOPS and asks you to
  re-run with sudo. Turn it back off with --user, or run: sudo bash tests.sh

Test-mode status (report the booleans and EXIT; no suite run, no conf change):
  --status               echo each mode's conf value, env override, resolved effective value,
                         and how many tests carry that mode's marker, then exit. Read-only.

Help:
  -h, --help             print this and exit.

Pass-through examples (forwarded to pytest verbatim):
  bash tests.sh -k pacman                run only tests matching "pacman"
  bash tests.sh tests/test_paths.py      run one file
  bash tests.sh -m root                  ONLY the root tier (needs --root / true env, and real UID 0)
EOF
}

# Collect the requested toggles. Each of the two pairs is mutually exclusive; the two
# pairs are independent, so `--online --root` sets both. NET_TOGGLE/ROOT_TOGGLE hold
# the requested value ("true"/"false") or "" if that pair was not touched.
NET_TOGGLE=""
ROOT_TOGGLE=""
ANY_TOGGLE=0
WANT_STATUS=0
set_pair() {                            # set_pair <var-name> <value> <flag-a> <flag-b>
    local cur; cur="$(eval "printf '%s' \"\$$1\"")"
    if [ -n "$cur" ] && [ "$cur" != "$2" ]; then
        echo "[tests] error: '$3' and '$4' are mutually exclusive -- pick one" >&2
        exit 2
    fi
    eval "$1=\$2"
    ANY_TOGGLE=1
}
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage; exit 0 ;;
        --status)  WANT_STATUS=1 ;;
        --online)  set_pair NET_TOGGLE  true  --online --offline ;;
        --offline) set_pair NET_TOGGLE  false --online --offline ;;
        --root)    set_pair ROOT_TOGGLE true  --root   --user ;;
        --user)    set_pair ROOT_TOGGLE false --root   --user ;;
    esac
done

# --status is a READ-ONLY report: it echoes each mode's persisted conf value, any env override, the
# RESOLVED effective value (env wins over conf, byte-identical to _testmodes.py), and a count of how
# many tests carry that mode's marker, then exits -- no venv BUILD, no sudo demand, and it NEVER writes
# the conf. (The count runs the venv's pytest collector ONLY if the venv already exists, so it stays
# instant and never builds; a fresh clone reports the count unavailable.) Handled in the early pass so
# it is instant. It cannot be combined with a toggle: a toggle MUTATES the conf while status READS it,
# so mixing them is ambiguous ("did you want the value before or after the flip?") -- refuse rather than
# guess. The only prior filesystem touch is the one-time conf auto-create above, so a --status on a
# fresh clone reports the both-off default rather than erroring.
if [ "$WANT_STATUS" -eq 1 ]; then
    if [ "$ANY_TOGGLE" -eq 1 ]; then
        echo "[tests] error: --status cannot be combined with a toggle (--online/--offline/--user/--root) -- it only reports" >&2
        exit 2
    fi
    # count_field <marker> <noun> -- the bracketed, plural-aware marker count for a status line. The
    # counting + formatting live in tests/_testmodes.py (the test-mode source of truth); we only invoke
    # it when the venv python already exists, so --status stays instant and never BUILDS the venv.
    count_field() {                        # count_field <marker> <noun>
        local marker="$1" noun="$2"
        if [ -x "$PY" ]; then
            "$PY" "$REPODIR/tests/_testmodes.py" --count-field "$marker" "$noun" "$PY" 2>/dev/null \
                || printf '[%s tests: unavailable]' "$noun"
        else
            printf '[%s tests: venv not built]' "$noun"   # no venv yet -> do NOT build here
        fi
    }
    # status_line <label> <key> <env-var-name> <env-token-fn> -- print one mode's conf/env/effective,
    # then a trailing count of how many tests carry that mode's marker (count_field above).
    # conf: conf_bool (the persisted file value). env: the token fn applied to the env var, shown as
    # its raw display or "(unset)" when the var is absent. effective: env wins ONLY when it parses to a
    # recognized token (true/false); an unset OR unrecognized env ABSTAINS to the conf -- exactly the
    # precedence network_enabled()/root_enabled() use, so `--status` never disagrees with a real run.
    status_line() {                        # status_line <label> <key> <envname> <tokenfn>
        local label="$1" key="$2" envname="$3" tokenfn="$4"
        local conf env_raw env_tok eff extra="" count
        conf="$(conf_bool "$key")"
        if [ -z "${!envname+x}" ]; then          # var UNSET (distinct from set-but-empty)
            env_raw="(unset)"; env_tok=unknown
        else
            env_raw="${!envname}"; env_tok="$("$tokenfn" "$env_raw")"
            [ -z "$env_raw" ] && env_raw="(empty)"        # set-but-empty: show it, still abstains
        fi
        if [ "$env_tok" = unknown ]; then eff="$conf"; else eff="$env_tok"; fi
        # A human-friendly gloss on the effective value (network reads online/offline; root reads its
        # run-vs-skip meaning) so the line is readable at a glance without decoding true/false.
        if [ "$key" = network ]; then
            [ "$eff" = true ] && extra="online, network tests RUN" || extra="offline, network tests SKIPPED"
        else
            [ "$eff" = true ] && extra="root tier ENABLED (needs UID 0)" || extra="user, root tests SKIPPED"
        fi
        count="$(count_field "$key" "$key")"
        printf '  %-8s conf=%-5s %s=%-9s -> effective: %-5s (%s)  %s\n' \
               "$label" "$conf" "$envname" "$env_raw" "$eff" "$extra" "$count"
    }
    echo "[tests] test mode status  (conf: ${MODESCONF#$REPODIR/}; env overrides the conf for one run)"
    status_line "network:" network QVM_TESTS_NETWORK net_env_token
    status_line "root:"    root    QVM_TESTS_ROOT    root_env_token
    exit 0
fi

if [ "$ANY_TOGGLE" -eq 1 ]; then
    # Read the CURRENT booleans (via the canonical conf_bool above) so a toggle of one pair
    # preserves the other. Missing/garbage -> false (fail closed), same as Python.
    net="$(conf_bool network)"
    root="$(conf_bool root)"
    [ -n "$NET_TOGGLE" ]  && net="$NET_TOGGLE"
    [ -n "$ROOT_TOGGLE" ] && root="$ROOT_TOGGLE"
    mkdir -p "$(dirname "$MODESCONF")"
    printf 'network = %s\nroot = %s\n' "$net" "$root" > "$MODESCONF"
    echo "[tests] test modes: network=$net root=$root  (saved to ${MODESCONF#$REPODIR/})"
    # A short, mode-specific hint for whichever pair(s) the caller actually flipped.
    if [ -n "$NET_TOGGLE" ]; then
        if [ "$net" = true ]; then
            echo "[tests] network-marked tests will now RUN. Toggle back with: bash tests.sh --offline"
        else
            echo "[tests] network-marked tests will be SKIPPED. Enable them with: bash tests.sh --online"
        fi
    fi
    if [ -n "$ROOT_TOGGLE" ]; then
        if [ "$root" = true ]; then
            echo "[tests] root-marked tests will now RUN (if actually UID 0). Toggle back with: bash tests.sh --user"
        else
            echo "[tests] root-marked tests will be SKIPPED. Enable them with: bash tests.sh --root"
        fi
    fi
    exit 0
fi

# --- 0. Pick the output mode. -----------------------------------------------
# Walk the args ONCE: pull out the (at most one) mode flag and keep everything
# else in PYTEST_ARGS to forward. `--` ends flag parsing -- anything after it is
# forwarded verbatim. Two mode flags (e.g. `-q -l`) is a hard error, not a
# silent last-one-wins.
MODE="mixed"
MODE_FLAG_SEEN=""
PYTEST_ARGS=()
seen_ddash=0
set_mode() {                            # set_mode <name> <flag-as-typed>
    if [ -n "$MODE_FLAG_SEEN" ] && [ "$MODE" != "$1" ]; then
        echo "[tests] error: '$MODE_FLAG_SEEN' and '$2' are mutually exclusive -- pick one output mode" >&2
        exit 2
    fi
    MODE="$1"
    MODE_FLAG_SEEN="$2"
}
for arg in "$@"; do
    if [ "$seen_ddash" -eq 1 ]; then
        PYTEST_ARGS+=("$arg"); continue
    fi
    case "$arg" in
        --)              seen_ddash=1 ;;
        -q|--quiet)      set_mode quiet "$arg" ;;
        -l|--loud)       set_mode loud  "$arg" ;;
        *)               PYTEST_ARGS+=("$arg") ;;
    esac
done

# --- Root tier demands sudo. -------------------------------------------------
# When the root tier is ENABLED (root = true in the conf, or QVM_TESTS_ROOT set truthy),
# the root-marked tests need UID 0 to do anything real -- so a plain `bash tests.sh` without
# sudo would only ever SKIP them, silently defeating the toggle the user just turned on.
# Refuse instead: stop here with a clear instruction to re-run under sudo. This runs on the
# NORMAL-RUN path only -- `--help` and every toggle flag (--root/--user/...) have already
# exited above, so flipping the switch never trips this; only actually RUNNING the suite does.
# It also runs BEFORE the venv build below, so an unprivileged root-mode run fails fast and
# cheap rather than after seconds of venv work.
#   * Effective mode is resolved EXACTLY as the run itself resolves it (env wins over the
#     file, via the canonical conf_bool), so the guard and the tests never disagree.
#   * QVM_ALLOW_NONROOT is a TEST-ONLY escape hatch: it lets a hermetic CI harness drive a
#     root-mode tests.sh as an ordinary user without the refusal. A real user never sets it,
#     so they still stop and are told to re-run under sudo.
# Resolve the effective root mode EXACTLY as _testmodes.root_enabled() does: the env var wins
# ONLY when it parses to a recognized boolean; any UNRECOGNIZED env value (empty, whitespace-only,
# or junk) makes the env ABSTAIN and we fall through to the conf file -- never to a bare `false`.
# Getting this precedence byte-identical to Python is what keeps the guard and pytest's conftest
# (both reading the same env var) from ever disagreeing and silently skipping the enabled tier.
# Three divergences an adversarial review caught, all fixed by matching _as_bool's normalize:
#   * folding: `QVM_TESTS_ROOT=TRUE`/`Yes`/`ON` -- Python lowercases, so truthy; the raw `case`
#     saw it as unrecognized -> false and waved the run through.
#   * trimming: `QVM_TESTS_ROOT=" true "` or a trailing newline from `$(...)` capture -- Python
#     _ascii_strip trims it truthy; an untrimmed `case` would not match.
#   * abstain: `QVM_TESTS_ROOT="  "` (whitespace-only) with `root = true` in the conf -- Python
#     reads the env as None and falls to the conf (true); the old `[ -n ]` test treated the
#     non-empty-but-blank value as "set" and skipped the conf, reading false. Now both fall through.
# root_env_token (defined up near conf_bool, also used by --status) echoes true|false|unknown after
# _as_bool's ASCII-trim + case-fold -- the single source of truth for parsing this env var.
ROOT_MODE="$(root_env_token "${QVM_TESTS_ROOT:-}")"
[ "$ROOT_MODE" = unknown ] && ROOT_MODE="$(conf_bool root)"   # env abstained -> the conf decides
if [ "$ROOT_MODE" = true ] && [ "$(id -u)" -ne 0 ] && [ -z "${QVM_ALLOW_NONROOT:-}" ]; then
    echo "[tests] the root test tier is ENABLED but you are not root." >&2
    echo "[tests] These tests need administrator rights. Please re-run with sudo:" >&2
    echo "            sudo bash tests.sh${*:+ $*}" >&2
    echo "[tests] Or turn the root tier back off (no sudo needed): bash tests.sh --user" >&2
    exit 1
fi

# --- 1. Ensure the venv exists. ---------------------------------------------
if [ ! -x "$PY" ]; then
    echo "[tests] creating venv at $VENV"
    python3 -m venv "$VENV"
fi

# --- 2. Install requirements only when they change. -------------------------
# Stamp the venv with a hash of requirements.txt. If the file is byte-identical
# to the last successful install, skip pip entirely (pip is slow even on a
# no-op). Edit requirements.txt and the next run reinstalls automatically.
REQ_HASH=""
if [ -f "$REQ" ]; then
    REQ_HASH="$(sha256sum "$REQ" | cut -d' ' -f1)"
fi
if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP" 2>/dev/null)" != "$REQ_HASH" ]; then
    echo "[tests] installing requirements"
    # pip runs quiet so a clean install stays silent, but a FAILING install must
    # not vanish: capture its output and dump it before exiting non-zero. A bare
    # `--quiet` swallows the real error (a yanked wheel, a version that dropped
    # support for this Python), leaving CI with just "exit code 1" and nothing to
    # diagnose. `pip_install` prints the captured log only on failure.
    pip_install() {
        local log
        log="$("$PY" -m pip install --quiet "$@" 2>&1)"
        local rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "[tests] pip install failed (exit $rc):" >&2
            printf '%s\n' "$log" >&2
        fi
        return "$rc"
    }
    pip_install --upgrade pip
    if [ -f "$REQ" ]; then
        pip_install -r "$REQ"
    fi
    echo "$REQ_HASH" > "$STAMP"
fi

# --- 3. Run pytest. ----------------------------------------------------------
# PYTHONPATH exposes qvm's single import root (libraries/) so tests can import the
# packages.hypervisor package. pytest options and the test path live in pyproject.toml.
export PYTHONPATH="$REPODIR/libraries${PYTHONPATH:+:$PYTHONPATH}"

# Do not write .pyc files. The tests import the source modules directly; a stale
# cached .pyc from an interrupted run can otherwise shadow a just-edited .py
# (same mtime) and make a test read old bytes. Compiling fresh every run costs a
# few ms on this tiny codebase and removes that whole class of confusion.
export PYTHONDONTWRITEBYTECODE=1

# Pin BOTH test modes for THIS run to whatever tests/test_modes.conf says (via the canonical
# conf_bool defined near the top), and export them so the two isolated log-copy runs (child
# subshells) resolve the SAME modes -- their repo copies do not contain the real conf file, so the
# env vars are how they learn it. An QVM_TESTS_NETWORK / QVM_TESTS_ROOT already set in the
# caller's environment WINS (lets CI or a one-off override without editing the file). A
# missing/empty/garbage value reads false (tier OFF) -- offline cannot hang, user needs no sudo.
if [ -z "${QVM_TESTS_NETWORK:-}" ]; then
    # Export the network mode as the legacy WORD (online/offline) so `-m network` docs and
    # any word-expecting reader keep working; _testmodes.py accepts both the word and true/false.
    [ "$(conf_bool network)" = true ] && export QVM_TESTS_NETWORK=online || export QVM_TESTS_NETWORK=offline
fi
if [ -z "${QVM_TESTS_ROOT:-}" ]; then
    export QVM_TESTS_ROOT="$(conf_bool root)"
fi

# Right-align the percentage and keep lines from wrapping. Below, pytest's stdout
# is a PIPE (we tee it), so pytest cannot query the terminal width and falls back
# to 80 -- long test ids then overflow and the [ NN%] column drifts. Resolve the
# REAL width once and export it so pytest formats to the actual screen exactly as
# it would on a bare tty. Try the cheapest source that works: an already-set
# COLUMNS, else the tty via stty, else tput, else 80. Each source is guarded so a
# headless run (no tty) never aborts the script: `nounset` is satisfied by the
# `${COLUMNS:-}` default, and -- because `set -o pipefail` propagates a pipe's
# failure and `errexit` would then kill us -- the stty/tput calls (which fail off
# a tty) each swallow their own non-zero status (`|| true`) so the pipeline stays
# zero and we simply fall through to the next source, ending at 80.
WIDTH="${COLUMNS:-}"
if [ -z "$WIDTH" ]; then WIDTH="$( { stty size 2>/dev/null || true; } | cut -d' ' -f2)"; fi
if [ -z "$WIDTH" ]; then WIDTH="$(tput cols 2>/dev/null || true)"; fi
[ -n "$WIDTH" ] || WIDTH=80
export COLUMNS="$WIDTH"

# Leave a spotless tree on EXIT, however we exit (pass, fail, or Ctrl-C). Two
# kinds of scratch get wiped, both gitignored and both treated as pollution here:
#   - .pytest_cache in the rootdir (pytest's scratch). We ALSO run pytest with
#     -p no:cacheprovider (below) so it is never written in the first place; this
#     rm is the belt to that suspenders.
#   - every __pycache__ in the tree. PYTHONDONTWRITEBYTECODE=1 above stops this
#     run from writing any, but a stray one from some other tool must not survive
#     a test run either -- so sweep them all. venv/ is pruned so we don't churn
#     its thousands of cached stdlib entries (matches clear.sh).
# logs/ is NOT swept here: it is this script's own output (logs/tests.log below);
# clearing it is clear.sh's job (clear.sh -l).
# The two off-screen log runs are children of this shell, each working inside a
# throwaway repo COPY under /tmp. On any exit (pass, fail, Ctrl-C) the trap kills
# any still-running child and removes every copy so nothing lingers after we go.
cleanup() {
    rm -rf "$REPODIR/.pytest_cache"
    kill "$P_LOG1" "$P_LOG2" 2>/dev/null || true
    for d in "${LOGCOPIES[@]}"; do [ -n "$d" ] && rm -rf "$d"; done
    find "$REPODIR" -type d -name venv -prune -o -type d -name __pycache__ -exec rm -rf {} +
}
# P_* are the off-screen log PIDs and LOGCOPIES the temp copy dirs, all set just
# before the run. Default them empty/empty-array so the trap is safe under nounset
# if we exit before they are populated.
P_LOG1=""; P_LOG2=""
LOGCOPIES=()
trap cleanup EXIT

# --- Per-mode pytest options -------------------------------------------------
# Each output mode runs pytest in its OWN native verbosity, so pytest emits the
# right layout directly -- no reconstruction, so no `-vv` artifact (wrapped skip
# reasons, digit walls) can leak into the leaner views.
#   -o addopts= wipes the -v pyproject bakes in, so OUR verbosity is the only one.
#   --color=yes forces color through the pipe (stdout is not a tty below).
#   -p no:cacheprovider keeps .pytest_cache from ever being written.
# Mode-specific:
#   mixed -> -ra              : pytest's own per-file grouped dots
#            (`tests/test_x.py .....`), gray-able header, short summary. The file
#            label prints in the terminal's default fg (white); dots green. Default.
#   quiet -> -q              : bare dots only, `s`/`F` inline. `-q` never prints an
#            inline skip REASON, so long reasons cannot wrap into junk lines.
#   loud  -> -vv -rfE --tb=long : one bright line per test, failures reported, full
#            tracebacks. The eyesore.
# These lead so a user's own -k/path in PYTEST_ARGS still applies and can override.
opts_for_mode() {                          # opts_for_mode <mode> -> echoes flags
    case "$1" in
        quiet) echo "-o addopts= -q --color=yes -p no:cacheprovider" ;;
        loud)  echo "-o addopts= -vv -rfE --tb=long --color=yes -p no:cacheprovider" ;;
        *)     echo "-o addopts= -ra --color=yes -p no:cacheprovider" ;;   # mixed
    esac
}

# Fresh logs every run: truncate all three so each holds exactly THIS run's
# transcript (color-stripped), mirroring compile.sh which truncates logs/*.log
# per launch. mkdir -p because logs/ is gitignored and may not exist yet.
mkdir -p "$LOGDIR"
: > "$LOG_MIXED"; : > "$LOG_LOUD"; : > "$LOG_QUIET"

# fit <mode> -- reformat a NATIVE pytest stream to the terminal WIDTH, in ONE awk
# pass (fflush per line -> live end to end). This is the ONLY reformatting: pytest
# already produced the correct layout for the mode, so awk never reconstructs dots.
# It does exactly three things, all width/color cosmetics:
#   * HEADER block (platform/rootdir:/configfile:/testpaths:/plugins:/collected ...)
#     -> gray. Context, not result. Anchored at line start on de-colored text so a
#     node id that merely CONTAINS "rootdir" is never caught. (The mixed per-file
#     LABEL is NOT a header line, so it keeps pytest's default white fg.)
#   * A per-test `::...VERDICT [ NN%]` line wider than the screen (loud, where a
#     param id can be a 500-char digit wall pytest does not truncate): cut at the
#     `[` that opens the param id, insert an ellipsis, keep the trailing
#     ` VERDICT [ NN%]`. The unreadable digits are DROPPED, not sampled. If the id
#     has no `[` (a long plain node name), fall back to a generic middle-truncate
#     that still preserves the tail verdict.
#   * Any OTHER over-wide line (a long traceback line, a wide summary) -> generic
#     middle-truncate (head + ellipsis + tail) so both ends survive.
# Lines that already fit keep their exact bytes and color. Blank lines and pytest's
# own spacing pass through untouched -- no synthesized or collapsed blanks.
fit() {
    awk -v W="$COLUMNS" '
    BEGIN { GRY="\033[90m"; RST="\033[0m" }
    function strip(s) { gsub(/\033\[[0-9;]*[a-zA-Z]/, "", s); return s }
    # generic middle-truncate of a PLAIN string to width W (head + ellipsis + tail).
    function mid(v,   keep,head,tail) {
        if (length(v) <= W) return v
        keep = W - 1; head = int(keep*0.55); tail = keep - head
        return substr(v,1,head) "\342\200\246" substr(v, length(v)-tail+1)
    }
    # a possibly-colored line: keep bytes+color if it fits, else strip+middle (gray).
    function fit_line(raw, bare) { return (length(bare) <= W) ? raw : GRY mid(bare) RST }
    # fit an over-wide per-test RESULT line by cutting at the param-id `[`. bare is
    # the de-colored text, shaped "file::name[HUGE_ID] VERDICT [ NN%]". Keep
    # everything up to and including "name[", an ellipsis, then the trailing
    # " VERDICT [ NN%]" -- anchored on the VERDICT WORD (from the space just before
    # it), so both the verdict and the percentage survive and the whole unreadable
    # id is DROPPED, not sampled. No `[` (a long plain node name) -> generic
    # middle-truncate. Colors are dropped on a truncated line (partial escapes would
    # corrupt); a fitting line never reaches here.
    function fit_result(bare,   lb, vpos, tail_start, headstr, tailstr, rest, off) {
        lb = index(bare, "[")                       # first "[" opens the param id
        if (lb == 0) return GRY mid(bare) RST       # no param id: generic middle
        # Find the LAST VERDICT word (the id itself can contain letters, so scan
        # from where the id opens and keep the rightmost match).
        vpos = 0; off = lb
        while (match(substr(bare, off), /(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)/)) {
            vpos = off + RSTART - 1                  # absolute index of this verdict
            off  = vpos + RLENGTH                    # continue past it for a later one
        }
        if (vpos == 0) return GRY mid(bare) RST      # no verdict found: generic middle
        tail_start = (vpos > 1 && substr(bare, vpos-1, 1) == " ") ? vpos-1 : vpos
        headstr = substr(bare, 1, lb)               # readable "file::name[" up to "["
        tailstr = substr(bare, tail_start)          # " VERDICT [ NN%]"
        # The verdict tail is non-negotiable; the head gets the rest. If the head
        # (a long path + long function name) itself overruns that budget, clip its
        # END -- keep the START, which is the readable name -- so we never spill the
        # digit wall back in via a balanced middle-truncate. Budget = W-1 for the
        # ellipsis. If even the tail alone will not fit (pathologically narrow
        # terminal), fall back to a generic middle so at least the percentage shows.
        if (length(tailstr) + 1 >= W) return GRY mid(bare) RST
        if (length(headstr) + 1 + length(tailstr) > W)
            headstr = substr(headstr, 1, W - 1 - length(tailstr))
        return GRY headstr "\342\200\246" tailstr RST
    }
    {
        bare = strip($0)
        # header block -> gray + width-fit.
        if (bare ~ /^(platform |rootdir:|configfile:|testpaths:|plugins:|cachedir:|collecting |collected )/) {
            print GRY mid(bare) RST
        # an over-wide per-test result line -> cut the param-id digit wall at "[".
        } else if (length(bare) > W && bare ~ /::/ && bare ~ / (PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)([ ]|\[|$)/) {
            print fit_result(bare)
        # everything else: keep verbatim if it fits, else generic middle-truncate.
        } else {
            print fit_line($0, bare)
        }
        fflush()
    }'
}

# The default run includes EVERYTHING, network-marked live tests included. The
# `network`-marked tests ping real external hosts and skip themselves when
# offline, so a plain `bash tests.sh` still passes without connectivity.
#
# Real-time output. pytest writes to a PIPE below (we filter it), and off a tty it
# lets its stream sit in a big block buffer -- so with plain piping nothing appears
# until the run is nearly over and it FEELS frozen. Two things fix that: `python -u`
# unbuffers the interpreter, and `stdbuf -oL` forces pytest's stdout to flush per
# LINE, so each row of dots / each test line reaches the screen the instant pytest
# emits it. The downstream awk fflushes per line too, so the pipeline is live end
# to end. stdbuf is coreutils and effectively always present; if it is somehow
# missing, fall back to plain (still correct, just block-buffered) rather than fail.
STDBUF=(stdbuf -oL)
command -v stdbuf >/dev/null 2>&1 || STDBUF=()

STRIP='s/\x1b\[[0-9;]*[a-zA-Z]//g'   # ANSI-color scrubber for the plain-text logs

# The mode shown on the terminal writes its OWN log directly from the terminal run
# (no extra pytest process). The OTHER TWO modes each need their own pytest run for
# a faithful log -- and those runs must NOT share this working directory with the
# terminal run: a few tests build C binaries INTO the source tree and rmtree them
# in teardown (test_*_does_not_pollute_the_repo_tree), so two runs of the suite in
# the same dir race on those paths (a real FileNotFoundError mid-copy, reproduced).
# So each background log run executes in its OWN throwaway COPY of the repo (12M,
# copied in well under a second), cwd + PYTHONPATH pointed at the copy, leaving the
# real tree untouched and the runs fully independent -- they run CONCURRENTLY with
# the terminal (wall time ~= one run) yet cannot collide. errexit is off around the
# whole block so a test failure never aborts before we read status + wait on sinks.
#
# other_modes <shown> -- echo the two modes that are NOT the one on screen.
other_modes() {
    case "$1" in
        quiet) echo "mixed loud" ;;
        loud)  echo "mixed quiet" ;;
        *)     echo "loud quiet" ;;   # mixed shown
    esac
}
log_path_for() {                           # log_path_for <mode> -> its logfile
    case "$1" in quiet) echo "$LOG_QUIET" ;; loud) echo "$LOG_LOUD" ;; *) echo "$LOG_MIXED" ;; esac
}

# run_log_isolated <mode> <logfile> <dir> -- mirror the repo into <dir> and run
# pytest there in <mode>, writing the fitted, color-stripped transcript to
# <logfile>. <dir> is created and recorded by the PARENT (below) so the EXIT trap
# can remove it -- a `LOGCOPIES+=` here would be lost, since this runs backgrounded
# in a subshell whose variable writes never reach the parent. Its pytest exit code
# is irrelevant (the terminal run is authoritative), so it is not propagated.
run_log_isolated() {                       # run_log_isolated <mode> <logfile> <dir>
    local mode="$1" logfile="$2" dir="$3" o
    # Mirror the repo minus the bits a run does not need (venv is reused via $PY; .git
    # and logs are irrelevant to a test run) -- keeps the copy tiny and fast. output/ and
    # cache/ are EXCLUDED too and this is not optional: they hold the built ISOs and the
    # package cache (tens of GB), which no test reads. Copying them once filled /tmp (a
    # 16G tmpfs) with a 47G copy, the copy failed on ENOSPC, and this function -- which
    # swallows copy errors (|| return 0) so a log run never aborts the suite -- left the
    # off-screen log EMPTY. Excluding the bulk gitignored dirs keeps the mirror at a few MB.
    #
    # One consequence, by design: a handful of tests read a pinned fixture FROM cache/ (e.g.
    # the calamares tarball the pkgbuild patch tests source). Absent from the copy, those
    # self-skip with their own "not present under cache/ (CI checkout)" reason -- exactly the
    # fresh-checkout path their authors already handle. They still PASS in the authoritative
    # terminal run (which has cache/ in place), so the suite RESULT is unchanged; only the two
    # off-screen LOGS may show those couple extra skips. That is the right trade: faithful,
    # never-empty logs beat copying 15G of cache to keep two skip lines out of a log.
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude venv --exclude .git --exclude logs --exclude output --exclude cache \
              "$REPODIR"/ "$dir"/ 2>/dev/null || return 0
    else
        # cp has no --exclude, and a copy-then-delete would still transit the tens of GB in
        # output/ + cache/ (ENOSPC on the tmpfs). So copy each top-level entry SELECTIVELY,
        # skipping the excluded names, so the bulk dirs are never read at all. Dotfiles too
        # (shopt dotglob) so .dockerignore/.gitattributes etc. come along.
        ( shopt -s dotglob nullglob
          for entry in "$REPODIR"/*; do
              case "$(basename "$entry")" in
                  venv|.git|logs|output|cache) continue ;;
              esac
              cp -a "$entry" "$dir"/ 2>/dev/null || exit 0
          done ) || return 0
    fi
    read -r -a o <<< "$(opts_for_mode "$mode")"
    # cwd = copy so repo-relative test paths resolve inside it; PYTHONPATH -> the
    # COPY's import roots so imported modules also write into the copy, never the
    # real tree. Reuse the real venv interpreter ($PY) -- the venv is not copied.
    ( cd "$dir" \
        && PYTHONPATH="$dir/libraries" \
           "${STDBUF[@]}" "$PY" -u -m pytest "${o[@]}" "${PYTEST_ARGS[@]}" 2>&1 ) \
        | fit "$mode" | sed -u -E "$STRIP" >> "$logfile"
}

set +o errexit
# Launch the two OFF-SCREEN log runs (isolated copies), concurrently. Create + record
# each copy dir HERE in the parent so the EXIT trap (via LOGCOPIES) always removes it,
# even though the run itself is backgrounded.
read -r -a OTHER <<< "$(other_modes "$MODE")"
DIR1="$(mktemp -d "${TMPDIR:-/tmp}/qvm-testlog.XXXXXX")"; LOGCOPIES+=("$DIR1")
DIR2="$(mktemp -d "${TMPDIR:-/tmp}/qvm-testlog.XXXXXX")"; LOGCOPIES+=("$DIR2")
run_log_isolated "${OTHER[0]}" "$(log_path_for "${OTHER[0]}")" "$DIR1" & P_LOG1=$!
run_log_isolated "${OTHER[1]}" "$(log_path_for "${OTHER[1]}")" "$DIR2" & P_LOG2=$!

# The TERMINAL run: pytest natively in the SELECTED mode, IN PLACE. Its fitted,
# colored stream goes to the screen AND (color-stripped) to that mode's own log --
# one process serves both. This is the authoritative run: its TRUE exit code is
# ${PIPESTATUS[0]} (stdbuf execs pytest and propagates its status, so this is
# pytest's own code, not tee's / awk's / sed's).
read -r -a TERM_OPTS <<< "$(opts_for_mode "$MODE")"
"${STDBUF[@]}" "$PY" -u -m pytest "${TERM_OPTS[@]}" "${PYTEST_ARGS[@]}" 2>&1 \
    | fit "$MODE" \
    | tee >(sed -u -E "$STRIP" >> "$(log_path_for "$MODE")")
status="${PIPESTATUS[0]}"
wait "$P_LOG1" "$P_LOG2"               # ensure both off-screen logs are fully written
set -o errexit

exit "$status"
