# Replica of the organizer judging container (features D-17, P0-02):
# Linux ARM64, Node.js 24.11.1, offline, read-only root, writable temp only.
# Built by scripts/judge.cjs with the repo as build context and the toolkit as a
# named build context ("toolkit"), so it works the same from Windows, WSL and Linux
# without bind mounts. Python is present ONLY so the toolkit's validate.py can run
# inside the replica; the submission itself never uses it.
FROM node:24.11.1-bookworm-slim AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*

FROM base
COPY --from=toolkit . /toolkit
COPY . /app
USER node
WORKDIR /app
