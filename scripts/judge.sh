#!/bin/sh
# Run a command inside the judging-container replica:
#   linux/arm64, Node 24.11.1, --read-only root, --network none, tmpfs /tmp,
#   repo mounted read-only at /app, toolkit read-only at /toolkit.
# Usage: sh scripts/judge.sh <command...>     e.g. sh scripts/judge.sh node kig.cjs compat
# On x86 hosts Docker emulates arm64 (QEMU): correct but slow; never use its timings.
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
TOOLKIT_DIR=${TOOLKIT_DIR:-"$REPO/../Track-4-Toolkit"}
IMAGE=${KIG_JUDGE_IMAGE:-kig-judge:24.11.1}

if [ "$#" -eq 0 ]; then
  echo "usage: sh scripts/judge.sh <command...>" >&2
  exit 2
fi
if [ ! -d "$TOOLKIT_DIR" ]; then
  echo "toolkit not found at $TOOLKIT_DIR (set TOOLKIT_DIR)" >&2
  exit 2
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build --platform linux/arm64 -t "$IMAGE" "$REPO/tools/judge" >&2
fi

TTY_FLAG=""
if [ -t 0 ] && [ -t 1 ]; then TTY_FLAG="-t"; fi

exec docker run --rm -i $TTY_FLAG \
  --platform linux/arm64 \
  --read-only \
  --network none \
  --tmpfs /tmp:rw,exec,mode=1777 \
  -e HOME=/tmp \
  -v "$REPO":/app:ro \
  -v "$TOOLKIT_DIR":/toolkit:ro \
  -w /app \
  "$IMAGE" "$@"
