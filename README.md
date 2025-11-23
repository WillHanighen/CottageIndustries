# CottageIndustries

To install dependencies:

```bash
bun install
```

To run:

```bash
bun start
```

or in dev

```bash
bun run dev
```

## Deployment

### Docker

1. Build the image:

```bash
docker build -t cottage-industries .
```

2. Run the container:

```bash
docker run -p 3000:3000 \
  --env-file .env \
  -v $(pwd)/data:/app/data \
  cottage-industries
```

> Note: We mount a volume to `/app/data` and use `--env-file .env` to pass configuration and secrets. Ensure your `.env` file has `DB_PATH=/app/data/database.db`.

### Environment Variables

The application is configured via the `.env` file. Ensure the following variables are set:

# Required

NODE_ENV        Set to "production" in deployment for security features.
SESSION_SECRET  Long random string used to sign sessions.
ADMIN_EMAIL     Email for the site’s admin user.

# Server

PORT            Defaults to 3000 if not set.

# Database

DB_PATH         Path to SQLite file. Defaults to ./database.db.

# OAuth (required if enabling login)

GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET

This project was created using `bun init` in bun v1.3.2. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
