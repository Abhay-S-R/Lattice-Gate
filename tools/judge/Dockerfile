# Replica of the organizer judging container (features D-17, P0-02):
# Linux ARM64, Node.js 24.11.1, offline, read-only root, writable temp only.
# Python is present ONLY so the toolkit's validate.py can run inside the replica;
# the submission itself never uses it.
FROM node:24.11.1-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
USER node
WORKDIR /app
