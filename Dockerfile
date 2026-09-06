FROM node:20-alpine AS builder

WORKDIR /usr/src/app/server
COPY server/package*.json ./
RUN npm ci --only=production

FROM node:20-alpine

# Set non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /usr/src/app

# Copy dependencies
COPY --from=builder /usr/src/app/server/node_modules ./server/node_modules

# Copy application files
COPY . .

# Change ownership
RUN chown -R appuser:appgroup /usr/src/app
USER appuser

WORKDIR /usr/src/app/server
EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

CMD ["node", "server.js"]
