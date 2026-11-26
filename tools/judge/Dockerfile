# Replica of the organizer judging container (features D-17, P0-02):
# Linux ARM64, Node.js 24.11.1, Python 3.12 + pqcrypto==0.4.0, offline,
# read-only root, writable temp only.
# Built by scripts/judge.cjs with the repo as build context and the toolkit as a
# named build context ("toolkit"), so it works the same from Windows, WSL and Linux
# without bind mounts. Python is used ONLY by the toolkit's validate.py and our
# interop test; the submission itself never uses it.
#
# Base is the official Python 3.12 image (the judging runtime's Python); the exact
# Node 24.11.1 binary and npm are copied in from the official Node image.
FROM node:24.11.1-bookworm-slim AS node

FROM python:3.12-slim-bookworm AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends libstdc++6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && PIP_ROOT_USER_ACTION=ignore python3 -m pip install --no-cache-dir pqcrypto==0.4.0 \
 && useradd --create-home --uid 1000 node

FROM base
COPY --from=toolkit . /toolkit
COPY . /app
USER node
WORKDIR /app
