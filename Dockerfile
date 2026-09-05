# ── MAILSENTRY AI — NATIONAL PRODUCTION DOCKERFILE ──────────────────
# Sovereign Cloud deployment: MeghRaj (NIC Cloud), AWS ap-south-1 (Mumbai)
# Base Image: Hardened Alpine Linux with Node.js 20 LTS
FROM node:20-alpine AS production

# Security: Set working directory & install dumb-init for proper PID 1 signal handling
RUN apk add --no-cache dumb-init
WORKDIR /app

# Copy dependency manifests first for Docker layer caching
COPY server/package*.json ./server/

# Install production dependencies only
WORKDIR /app/server
RUN npm ci --only=production && npm cache clean --force
WORKDIR /app

# Copy all application assets, frontend, and backend modules
COPY . .

# Security hardening: Run as non-root user
USER node

# Networking & Health Monitoring
EXPOSE 3000
ENV NODE_ENV=production
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server/server.js"]
