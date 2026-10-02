#!/usr/bin/env bash
#
# qvm -- build entry point.
#
# Compiles the flat Python modules in libraries/ into a SINGLE self-contained binary with
# Nuitka (--onefile), written to output/qvm. Nuitka compiles Python -> C -> a native
# executable: a slower build than a bytecode freezer, but a tighter, faster binary and no
# .spec file. The whole build is a plain user-space run: there is NO pacman/mkarchiso here,
# so -- unlike azzio's compile.sh -- this needs no sudo and no PTY re-exec. It mirrors
# azzio's compile.sh in the parts that matter for a build entry point: it truncates its log
# per launch, keeps a stopwatch that reports the build duration on success AND failure, and
# exports PYTHONDONTWRITEBYTECODE=1 so no __pycache__ litters the source tree.
#
# The frozen binary runs the entry FLAT (libraries/qvm_main.py does `import
# command_line_interface`), so the modules load as bare siblings exactly as from source.
# --include-module names every sibling so Nuitka carries the whole app even though the
# bare `import <sibling>` lines are resolved only at runtime via qvm_main's sys.path insert.
# Crucially the launcher does NOT chdir: the VM identity derives from the caller's CWD via
# Config.from_cwd(), and Nuitka's onefile bootstrap leaves cwd untouched, so a `qvm` invoked
# inside /some/project resolves THAT directory's VM -- the single most important correctness
# property of the port, preserved through freezing.
#
# Nuitka's scratch (the qvm_main.build/ generated .c/.o, the .dist and onefile temp dirs)
# is a reusable compile cache, so it goes under qvm's cache/ dir (gitignored, wiped by
# ./clear.sh) via --output-dir; the finished binary is then copied OUT to output/qvm, which
# stays the delivered-artifact dir. ZERO build scratch lands in the repo root.
#
# ARGS: any args are passed straight through to Nuitka (e.g. --show-progress).
# Requires (system): python, python-pip, gcc (see packages_x86_64). compile.sh is
# self-bootstrapping like tests.sh: it builds cache/venv and installs requirements.txt
# (nuitka + patchelf) into it on first run, so a fresh checkout just runs ./compile.sh.

set -o errexit
set -o nounset
set -o pipefail

REPODIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPODIR"

PKGDIR="$REPODIR/libraries"
ENTRY="$REPODIR/libraries/qvm_main.py"
OUTDIR="$REPODIR/output"
CACHEDIR="$REPODIR/cache/nuitka"
LOGDIR="$REPODIR/logs"
LOG="$LOGDIR/compile.log"
BINNAME="qvm"
mkdir -p "$LOGDIR" "$OUTDIR" "$CACHEDIR"

# Never scatter __pycache__ around the source tree. Exported before any work so every
# child (Nuitka, the Python it runs) inherits it. This repo treats __pycache__ as
# pollution -- see clear.sh / tests.sh.
export PYTHONDONTWRITEBYTECODE=1

# The build runs out of a self-contained venv under cache/ (gitignored). compile.sh OWNS
# that venv: it is created on first run and requirements.txt (nuitka + patchelf) installed
# into it (just below, after the stopwatch starts so the install time is counted). Declared
# here; the bootstrap that may create it runs after the log/trap are set up.
VENV="$REPODIR/cache/venv"
PY="$VENV/bin/python"
REQ="$REPODIR/requirements.txt"
STAMP="$VENV/.requirements.installed"

# Stopwatch: format a whole-second duration as e.g. "1h 04m 09s" / "7m 32s" / "12s".
# Reported at the very end on success AND failure, mirroring azzio's compile.sh.
_format_duration() {
    local secs=$1 h m s
    h=$(( secs / 3600 )); m=$(( (secs % 3600) / 60 )); s=$(( secs % 60 ))
    if   [ "$h" -gt 0 ]; then printf '%dh %02dm %02ds' "$h" "$m" "$s"
    elif [ "$m" -gt 0 ]; then printf '%dm %02ds' "$m" "$s"
    else                      printf '%ds' "$s"
    fi
}

# Start the stopwatch and truncate the log so each launch overwrites the previous run's.
_COMPILE_START="$(date +%s)"
: > "$LOG"

# Report the elapsed time on EVERY exit (success, failure, or Ctrl-C), then let the real
# exit code propagate. Trapped so a Nuitka failure still prints how long it ran.
_report() {
    local rc=$?
    local elapsed=$(( $(date +%s) - _COMPILE_START ))
    local line
    if [ "$rc" -eq 0 ]; then
        line="[time] Compile finished in $(_format_duration "$elapsed")."
    else
        line="[time] Compile FAILED after $(_format_duration "$elapsed") (exit $rc)."
    fi
    echo "$line"
    echo "$line" >> "$LOG" 2>/dev/null || true
}
trap _report EXIT

# --- Self-bootstrap the build venv (mirrors tests.sh) ------------------------
# Create cache/venv on first run and install requirements.txt (nuitka + patchelf) into it,
# so a fresh checkout builds with a bare `./compile.sh` -- no manual venv steps. Everything
# lives in cache/venv; nothing global is touched. Runs AFTER the stopwatch/log/trap so the
# install time is counted and any failure is timed + reported.
if [ ! -x "$PY" ]; then
    BOOT="$(command -v python3 || true)"
    [ -n "$BOOT" ] || { echo "[compile] no python3 to build the venv -- pacman -S python python-pip" | tee -a "$LOG" >&2; exit 1; }
    echo "[compile] creating venv at $VENV" | tee -a "$LOG"
    "$BOOT" -m venv "$VENV" >>"$LOG" 2>&1
fi

# Install requirements only when they change: stamp the venv with a hash of requirements.txt
# and skip pip entirely when byte-identical to the last successful install.
REQ_HASH=""
[ -f "$REQ" ] && REQ_HASH="$(sha256sum "$REQ" | cut -d' ' -f1)"
if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP" 2>/dev/null)" != "$REQ_HASH" ]; then
    echo "[compile] installing build requirements (nuitka, patchelf, ...)" | tee -a "$LOG"
    # pip runs quiet, but a FAILING install must not vanish: capture its output and dump it
    # before exiting non-zero (a bare --quiet would leave just "exit 1" with nothing to read).
    _pip_install() {
        local out rc
        out="$("$PY" -m pip install --quiet "$@" 2>&1)"; rc=$?
        printf '%s\n' "$out" >> "$LOG" 2>/dev/null || true
        [ "$rc" -ne 0 ] && { echo "[compile] pip install failed (exit $rc):" >&2; printf '%s\n' "$out" >&2; }
        return "$rc"
    }
    _pip_install --upgrade pip
    [ -f "$REQ" ] && _pip_install -r "$REQ"
    echo "$REQ_HASH" > "$STAMP"
fi

# Nuitka's onefile mode on Linux shells out to `patchelf`; requirements.txt ships it as a
# pip wheel that drops its binary in the venv's bin/. Put that bin dir FIRST on PATH so
# Nuitka finds it without a separate system install (a system patchelf still works too).
export PATH="$VENV/bin:$PATH"

# Safety net: after the bootstrap above nuitka should import. If it still does not (e.g. the
# venv predates the nuitka pin and the stamp was stale), fail with a clear, logged message.
if ! "$PY" -c "import nuitka" >>"$LOG" 2>&1; then
    echo "[compile] Nuitka still not importable for $PY after bootstrap -- see $LOG" | tee -a "$LOG" >&2
    echo "[compile] Try a clean rebuild: ./clear.sh -c && ./compile.sh" | tee -a "$LOG" >&2
    exit 1
fi

# Every sibling module is named as an explicit include: the flat `import <sibling>` lines
# resolve only at runtime (via qvm_main's sys.path insert), which Nuitka's static analysis
# does not always follow. Naming them all guarantees the frozen binary carries the whole app.
MODULES=(
    checks command_line_interface configuration configuration_defaults
    configuration_schema configuration_watcher graphics host_resources
    qemu_command ssh_connect virtual_machine vm_instances vm_lifecycle vm_share
)
INCLUDE_ARGS=()
for m in "${MODULES[@]}"; do INCLUDE_ARGS+=(--include-module="$m"); done

echo "[compile] building $BINNAME (Nuitka --onefile) -> output/$BINNAME" | tee -a "$LOG"
echo "[compile] interpreter: $PY" | tee -a "$LOG"

# --onefile                 : one self-contained executable.
# --output-filename         : the binary is `qvm` (the command every caller invokes on PATH).
# --output-dir=CACHEDIR     : all build scratch (.build/.dist/onefile temp) under cache/.
# --assume-yes-for-downloads: onefile may fetch its bootstrap helper (appimage) -- answer
#                    yes non-interactively so no PTY is needed.
# --follow-imports          : pull every reachable module into the binary.
# --company-name/--product-name: cosmetic metadata; harmless, keeps output tidy.
# --python-flag=-O          : build with assertions off / __debug__ False (release).
"$PY" -u -m nuitka \
    --onefile \
    --output-filename="$BINNAME" \
    --output-dir="$CACHEDIR" \
    --follow-imports \
    "${INCLUDE_ARGS[@]}" \
    --assume-yes-for-downloads \
    --python-flag=-O \
    --company-name=qvm \
    --product-name=qvm \
    "$@" \
    "$ENTRY" 2>&1 | tee -a "$LOG"

# PIPESTATUS[0] is Nuitka's own exit (not tee's). errexit is satisfied because the
# pipeline's status is tee's 0; check Nuitka explicitly and fail on a nonzero build.
rc="${PIPESTATUS[0]}"
if [ "$rc" -ne 0 ]; then
    echo "[compile] Nuitka failed (exit $rc) -- see $LOG" | tee -a "$LOG" >&2
    exit "$rc"
fi

# Nuitka writes the onefile binary as <output-dir>/<output-filename> (the .bin suffix is
# Windows-only). Copy it OUT to output/ so output/ stays the delivered-artifact dir and
# cache/ is pure scratch.
BUILT=""
for cand in "$CACHEDIR/$BINNAME" "$CACHEDIR/$BINNAME.bin"; do
    [ -x "$cand" ] && { BUILT="$cand"; break; }
done
if [ -z "$BUILT" ]; then
    echo "[compile] build reported success but no onefile binary found under $CACHEDIR" | tee -a "$LOG" >&2
    exit 1
fi
install -m 755 "$BUILT" "$OUTDIR/$BINNAME"

if [ ! -x "$OUTDIR/$BINNAME" ]; then
    echo "[compile] build reported success but output/$BINNAME is missing" | tee -a "$LOG" >&2
    exit 1
fi

echo "[compile] done: $OUTDIR/$BINNAME" | tee -a "$LOG"
echo "[compile] install it with: sudo install -m 755 output/$BINNAME /usr/bin/" | tee -a "$LOG"
