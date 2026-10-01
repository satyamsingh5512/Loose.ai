# loose.ai

loose.ai is a SaaS platform for making real code changes to an organization's repositories through a chat interface with a live preview, powered by an AI coding agent running in an isolated cloud sandbox. Users bring their own model API key (BYOK). Non-technical contributors use Simple Mode (plain English, live preview, no code); developers use Pro Mode (diffs, tool calls, terminal, plan mode, checkpoints). See [`spec.md`](./spec.md) for the full product spec.

## Repository layout

| Path              | Package          | What                                                                     |
| ----------------- | ---------------- | ------------------------------------------------------------------------ |
| `apps/server`     | `@loose/server`  | Express 5 REST API, Prisma 6 (PostgreSQL), Redis (rate limits, idempotency) |
| `apps/web`        | `@loose/web`     | React 18 + Vite 7 + Tailwind 4 SPA                                       |
| `packages/shared` | `@loose/shared`  | Error catalog, envelopes, enums, constants, Zod DTOs, WS/runner contracts |

## Prerequisites

- [Bun](https://bun.sh) 1.4.2 (`packageManager` in `package.json`)
- Node.js 22
- Docker (for PostgreSQL 16 and Redis 7)

## Local setup

```bash
bun install

# PostgreSQL + Redis (localhost only)
docker compose up -d postgres redis      # if the compose plugin is installed (= bun run db:up)
# or, without compose:
docker run -d --name loose-postgres -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=loose -e POSTGRES_PASSWORD=loose -e POSTGRES_DB=loose postgres:16-alpine
docker run -d --name loose-redis -p 127.0.0.1:6379:6379 redis:7-alpine

# Server environment
cp apps/server/.env.example apps/server/.env
# Fill in SESSION_SECRET and LOCAL_KMS_MASTER_KEY (32 random bytes, base64):
#   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
# OAuth client ids/secrets are optional locally; without them /auth/<provider> returns LSE-AUTH-004.

bun run db:generate   # prisma generate
bun run db:migrate    # prisma migrate dev (applies migrations to the dev database)
```

The server validates its environment at boot and refuses to start on bad config (it prints the variable names, never values).

## Development

```bash
bun run dev           # API on http://localhost:4000, web on http://localhost:5173 (proxies /api and /ws)
```

Other scripts (all via Turborepo from the repo root):

```bash
bun run build         # build every package
bun run typecheck
bun run lint
bun run format:check  # or `bun run format` to fix
bun run test          # runs package test suites one at a time (--concurrency=1)
```

Server tests need PostgreSQL and Redis running. They create and migrate a separate `loose_test` database (override with `TEST_DATABASE_URL`) and use Redis db 15; all external HTTP (Anthropic, GitHub, OAuth providers) is mocked with MSW.

Production-style run of the API: `bun run --cwd apps/server build && bun run --cwd apps/server start` (`start` loads `apps/server/.env` if present). Health endpoints: `GET /healthz` (liveness) and `GET /readyz` (DB + Redis).

## Status

- Phase 1 (Foundation) and Phase 2 (Org & Keys) are implemented: OAuth sign-in (Google, GitHub), sessions, CSRF, users, BYOK Anthropic keys (live-validated, envelope-encrypted), personal API tokens, orgs, members, invites, policy, audit log, GitHub repo listing + inbound webhook, project CRUD and project memory.
- Later-phase API routes (template builds, smoke tests, sessions, usage, webhooks, extensions, …) are mounted but answer `503 LSE-SYS-007`; the corresponding web pages are placeholders.

## Auth design note

The `lucia` and `arctic` npm packages are deprecated, so the server implements Lucia-style sessions directly (random session tokens, only their SHA-256 hash stored, sliding expiry) and hand-rolls the OAuth flows (Google with PKCE, GitHub) using `node:crypto` and `fetch`. Session cookie `loose_session` is HttpOnly, SameSite=Lax and Secure in production. State-changing requests need a signed double-submit CSRF token (`loose_csrf` cookie echoed in `x-csrf-token`); Bearer-token requests and the GitHub webhook are exempt.

## Dev login (security note)

`POST /api/v1/auth/dev-login` signs in as any email without a password, so local development works without OAuth apps. It is mounted only when `NODE_ENV !== 'production'` **and** `DEV_LOGIN_ENABLED=true`; a test asserts the route returns 404 in production even if the flag is set. Never set `DEV_LOGIN_ENABLED=true` on a deployed environment.
# Loose.ai
