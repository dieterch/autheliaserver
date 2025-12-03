# Stage 1: Hol die Authelia-Binary aus dem offiziellen Image
FROM authelia/authelia:latest AS authelia_source

# Stage 2: Node App
FROM node:20-slim
# FROM node:20-bullseye-slim

# Install tini for proper signal handling
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Die Authelia Binary in unseren Container kopieren
COPY --from=authelia_source /app/authelia /usr/local/bin/authelia

# COPY package.json package-lock.json /app/
COPY package.json /app/
# RUN npm ci --no-audit --no-fund
RUN npm install --no-audit --no-fund

# copy app sources (expected to be mounted/overridden during development)
COPY . /app

EXPOSE 3000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "app.mjs"]
