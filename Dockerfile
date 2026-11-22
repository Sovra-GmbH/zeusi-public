# zeusi-mcp image for Fly (docs/hosting.md). Build only: nothing here deploys.
# The container runs the authenticated hosted server (`node dist/mcp.js --hosted`) through
# scripts/fly-entrypoint.sh, as the unprivileged `node` user. No secrets, hosts or keys are
# baked in: the database service file and read password are Fly secrets set at deploy time
# (the opt-in write service adds two more; docs/hosting.md "Write service").

FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
# Personal workspaces are built from these files at sign-up (src/tenant-ddl.ts). SQL only, no secrets.
COPY migrations ./migrations
# Listing icons only (GET /favicon.png and /favicon.svg). The rest of site/ stays out of the image.
COPY site/favicon.svg site/logo-512.png ./brand/
COPY scripts/fly-entrypoint.sh /app/scripts/fly-entrypoint.sh
RUN chmod 755 /app/scripts/fly-entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/app/scripts/fly-entrypoint.sh"]
