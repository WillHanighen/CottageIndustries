# Stage 1: Build
FROM oven/bun:1 AS base
WORKDIR /app

# Install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy source code
COPY . .

# Build CSS (and other assets if any)
RUN bun run build

# Stage 2: Production Release
FROM oven/bun:1 AS release
WORKDIR /app

# Install production dependencies only
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy source files
COPY --from=base /app/server.ts ./server.ts
COPY --from=base /app/database.ts ./database.ts
COPY --from=base /app/views ./views
COPY --from=base /app/public ./public

# Expose port
EXPOSE 3000

# Start the server
CMD ["bun", "server.ts"]

