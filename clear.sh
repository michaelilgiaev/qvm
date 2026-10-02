#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  cat <<'EOF'
Usage: clear.sh [-o] [-l] [-c] [-h]

Clears the build tree. With NO flags it clears everything (the default):
output/, logs/, cache/, every __pycache__ in the project, and .pytest_cache/.

Pass flags to clear only PART of the tree (flags combine):
  -o, --output   clear only output/
  -l, --logs     clear only logs/
  -c, --cache    clear only cache/  (also sweeps __pycache__ and .pytest_cache/)
  -h, --help     show this help and exit

cache/ is qvm's single scratch root: the Nuitka build cache AND the test/build
venv live there, so clearing it forces a cold recompile and a fresh venv.

Examples:
  clear.sh            clear output/, logs/, cache/, __pycache__, .pytest_cache (all)
  clear.sh -o -l      clear output/ and logs/ only (leaves cache/, __pycache__, .pytest_cache)
  clear.sh -c         clear cache/, __pycache__ and .pytest_cache only
EOF
}

# Selective flags: without any, clear EVERYTHING (the default). With one or more, clear only
# the selected targets. __pycache__ and .pytest_cache are swept WITH cache -- so -c (or the
# no-flag default that selects cache anyway) sweeps them, while -o/-l alone leave them.
# Unknown flags are rejected non-zero with usage.
do_output=0
do_logs=0
do_cache=0
any_flag=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) do_output=1; any_flag=1 ;;
    -l|--logs)   do_logs=1;   any_flag=1 ;;
    -c|--cache)  do_cache=1;  any_flag=1 ;;
    -h|--help)   usage; exit 0 ;;
    *)
      echo "clear.sh: unknown option '$1'" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done
if [ "$any_flag" -eq 0 ]; then       # no flags -> the everything-clear
  do_output=1
  do_logs=1
  do_cache=1
fi
# __pycache__ / .pytest_cache ride with cache (or the no-flag default that selects cache).
sweep_pyc="$do_cache"

# Delete each build dir and SAY what happened to it. Without this the script was silent, so
# you could not tell an already-clean tree from a failed delete.
#   - dir missing            -> nothing to do
#   - dir present, rm works  -> report it was removed (with its prior size)
#   - dir present, rm fails  -> report it survived (permissions?)
# Only the selected build dirs (order preserved: logs, cache, output). With no flags all three
# are selected, so this is the full list.
targets=()
[ "$do_logs" -eq 1 ]   && targets+=(logs)
[ "$do_cache" -eq 1 ]  && targets+=(cache)
[ "$do_output" -eq 1 ] && targets+=(output)
deleted=0
for d in "${targets[@]}"; do
  if [ ! -e "$d" ]; then
    echo "  [ skip    ] $d/ -- not present, nothing to delete"
    continue
  fi
  size="$(du -sh "$d" 2>/dev/null | cut -f1)"
  # Do not let a single failed rm abort the loop (set -e): capture its status so the
  # remaining dirs are still attempted and reported.
  if rm -rf "$d"; then
    echo "  [ deleted ] $d/ (was ${size:-?})"
    deleted=$((deleted + 1))
  else
    echo "  [ FAILED  ] $d/ still present -- could not remove (permissions?)"
  fi
done

# Sweep the Python pollution: every __pycache__ (pytest/imports scatter them under tests/,
# libraries/, ...) and .pytest_cache/. Both gitignored, both build junk, and a stale
# __pycache__ can shadow a just-edited module. They ride WITH cache (the -c flag or the
# no-flag default), left alone by -o/-l. cache/ itself was already removed above, so this
# only catches the ones scattered OUTSIDE cache/.
pollution_deleted=0
if [ "$sweep_pyc" -eq 1 ]; then
  echo
  pyc_found=0
  while IFS= read -r -d '' pc; do
    pyc_found=$((pyc_found + 1))
    if rm -rf "$pc"; then
      pollution_deleted=$((pollution_deleted + 1))
    else
      echo "  [ FAILED  ] $pc -- could not remove (permissions?)"
    fi
  done < <(find . -type d -name __pycache__ -print0)

  if [ "$pyc_found" -eq 0 ]; then
    echo "  [ skip    ] __pycache__ -- none found in the tree"
  else
    echo "  [ deleted ] $pyc_found __pycache__ director$( [ "$pyc_found" -eq 1 ] && echo y || echo ies )"
  fi

  # .pytest_cache is pytest's scratch dir at the repo root -- same family as __pycache__
  # (Python/pytest pollution, gitignored). tests.sh runs pytest with -p no:cacheprovider so
  # it is not created there, but a bare `pytest` could still make one; sweep it with cache.
  if [ -e ".pytest_cache" ]; then
    if rm -rf ".pytest_cache"; then
      echo "  [ deleted ] .pytest_cache/"
      pollution_deleted=$((pollution_deleted + 1))
    else
      echo "  [ FAILED  ] .pytest_cache/ -- could not remove (permissions?)"
    fi
  else
    echo "  [ skip    ] .pytest_cache/ -- not present"
  fi
fi

echo
total=$((deleted + pollution_deleted))
if [ "$total" -eq 0 ]; then
  echo "Nothing was deleted -- the tree was already clean."
elif [ "$sweep_pyc" -eq 1 ]; then
  echo "Removed $deleted build director$( [ "$deleted" -eq 1 ] && echo y || echo ies )" \
       "and $pollution_deleted Python artifact$( [ "$pollution_deleted" -eq 1 ] && echo '' || echo s )."
else
  echo "Removed $deleted build director$( [ "$deleted" -eq 1 ] && echo y || echo ies )."
fi
