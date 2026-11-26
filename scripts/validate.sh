#!/bin/sh
# Run the organizer toolkit's validate.py against the root adapter and keep the
# output as evidence (features P0-09). Exit status is validate.py's:
# 0 pass, 1 behaviour failure, 2 setup/execution failure, 3 format failure.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
TOOLKIT_DIR=${TOOLKIT_DIR:-"$REPO/../Track-4-Toolkit"}
case "$TOOLKIT_DIR" in /*) ;; *) TOOLKIT_DIR="$REPO/$TOOLKIT_DIR" ;; esac

if [ ! -f "$TOOLKIT_DIR/validate.py" ]; then
  echo "validate.py not found in $TOOLKIT_DIR (set TOOLKIT_DIR)" >&2
  exit 2
fi

COMMIT=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo nogit)
OUT_DIR=${KIG_EVIDENCE_DIR:-"$REPO/evidence"}
OUT="$OUT_DIR/validate-$COMMIT.txt"

if mkdir -p "$OUT_DIR" 2>/dev/null && [ -w "$OUT_DIR" ]; then
  python3 "$TOOLKIT_DIR/validate.py" --entry "$REPO/track4_service.cjs" > "$OUT" 2>&1
  STATUS=$?
  cat "$OUT"
  echo "evidence: $OUT (exit $STATUS)"
else
  # Read-only checkout (judging replica): print only.
  python3 "$TOOLKIT_DIR/validate.py" --entry "$REPO/track4_service.cjs"
  STATUS=$?
fi
exit $STATUS
