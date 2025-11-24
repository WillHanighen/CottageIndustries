# Stage 1: Build
FROM oven/bun:1 AS base
WORKDIR /app

# Install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy source code
COPY . .

# Build CSS and bundled assets (if applicable)
RUN bun run build

# Stage 2: Production Release
FROM oven/bun:1 AS release
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy everything from base (compiled assets AND source files)
COPY --from=base /app ./

EXPOSE 3000

# Start the server
CMD ["bun", "server.ts"]
