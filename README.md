# loose.ai

loose.ai is a SaaS platform for making real code changes to an organization's repositories through a chat interface with a live preview, powered by an AI coding agent running in an isolated cloud sandbox. Users bring their own model API key (BYOK). Non-technical contributors use Simple Mode (plain English, live preview, no code); developers use Pro Mode (diffs, tool calls, terminal, plan mode, checkpoints). See [`spec.md`](./spec.md) for the full product spec.

## Repository layout

| Path                     | Package         | What                                                                        |
| ------------------------ | --------------- | --------------------------------------------------------------------------- |
| `apps/server`            | `@loose/server` | Express 5 REST API, Prisma 6 (PostgreSQL), Redis (rate limits, idempotency) |
| `apps/web`               | `@loose/web`    | React 18 + Vite 7 + Tailwind 4 SPA                                          |
| `packages/shared`        | `@loose/shared` | Error catalog, envelopes, enums, constants, Zod DTOs, WS/runner contracts   |
| `packages/runner`        | `@loose/runner` | In-sandbox agent runner (Claude Agent SDK; deterministic mock mode)         |
| `packages/sdk`           | `@loose/sdk`    | TypeScript client for runs, SSE, projects, sessions, and webhook helpers    |
| `packages/cli`           | `@loose/cli`    | `loose` command-line client built on the SDK                                |
| `packages/github-action` | `loose-ai/run`  | Bundled Node 20 GitHub Action for CI-triggered runs                         |
| `templates/base`         | —               | e2b base template definition + service install steps                        |

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

The web app must be served from the origin in `APP_URL`: the WebSocket only accepts cookie-authenticated connections whose `Origin` matches it (the server logs `ws upgrade rejected` with `reason: bad_origin` otherwise, and the UI signs you out). `bun run --cwd apps/web preview` serves the built bundle on port 4173, so set `APP_URL=http://localhost:4173` while using it.

## Platform API, SDK, CLI and Action

Headless runs use Bearer tokens against `API_URL/api/v1`. Grant both `runs:write` and `runs:read` when a client starts and waits for runs; scopes do not imply one another. Add `projects:read` for project listing and `org:read` when the CLI must discover the token's organization.

```bash
# Once the workspace CLI is built/linked as `loose`:
loose login --token loose_pat_... --api-url http://localhost:4000/api/v1
loose projects --org <org-id>
loose run "Fix the failing tests" --project acme/site --pr
loose runs list
```

The same flow through `@loose/sdk`:

```ts
import { LooseClient } from '@loose/sdk';

const loose = new LooseClient({
  apiUrl: 'https://app.loose.ai/api/v1',
  token: process.env.LOOSE_TOKEN!,
});
const run = await loose.runs.create({
  project: 'acme/site',
  prompt: 'Fix the failing tests',
  options: { createPr: true },
});
const finished = await loose.runs.wait(run.id);
console.log(finished.status, finished.prUrl);
```

For CI, `packages/github-action` builds the bundled Node 20 `loose-ai/run` Action. Its required token should be stored as a GitHub Actions secret and needs `runs:read` plus `runs:write`:

```yaml
- uses: loose-ai/run@v1
  with:
    token: ${{ secrets.LOOSE_TOKEN }}
    project: acme/site
    prompt: Fix the failing tests and open a minimal pull request.
    create-pr: true
```

Inbound automation additionally uses these optional server variables; an endpoint returns `503 LSE-SYS-007` until its secret is configured:

| Variable                | Purpose                                                            |
| ----------------------- | ------------------------------------------------------------------ |
| `GITHUB_WEBHOOK_SECRET` | Verifies GitHub issue-label, PR-comment, and pull-request webhooks |
| `SLACK_SIGNING_SECRET`  | Verifies `/api/v1/integrations/slack/commands`                     |
| `LINEAR_WEBHOOK_SECRET` | **Deprecated, unused** (see below)                                 |
| `JIRA_WEBHOOK_SECRET`   | **Deprecated, unused** (see below)                                 |

Linear and Jira are credentialed **per trigger**, not per server: each trigger's webhook URL
(`/api/v1/integrations/{linear,jira}/webhook/<trigger-token>`) and its own signing secret are
shown with the trigger in Org Settings → Integrations and derived from `SESSION_SECRET`. A
request is therefore bound to exactly one trigger and one organization, and the global
`LINEAR_WEBHOOK_SECRET` / `JIRA_WEBHOOK_SECRET` variables are no longer read (they allowed one
tenant to fire another tenant's trigger). Calling the old secret-less paths returns
`401 LSE-AUTH-009`.

Outbound webhook signing secrets are generated per webhook and shown only once in Org Settings; no server environment variable is required. See `packages/github-action/README.md` for a complete workflow.

### Dependency overrides

`bun audit` must stay clean (CI fails otherwise). Two transitive dev-tool dependencies are pinned in the root `package.json` `overrides` because no released parent version ships the fix yet:

| Override              | Fixes                                                    | Pulled in by                                                     | Remove when                                             |
| --------------------- | -------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------- |
| `deepmerge-ts: 8.0.2` | GHSA-ggr8-5vv4-36mx (high, stack exhaustion; `<8.0.0`)   | `prisma` CLI → `@prisma/config` (pins 7.1.5, also in Prisma 7.x) | a stable `@prisma/config` depends on `deepmerge-ts` ≥ 8 |
| `esbuild: 0.28.2`     | GHSA-g7r4-m6w7-qqqr (low, Windows dev server; `<0.28.1`) | `tsup` 8.5.1 (requires `^0.27`)                                  | a `tsup` release allows esbuild ≥ 0.28.1                |

Both only affect build and CLI tooling, not the shipped server or web bundle.

## Status

- Phase 1 (Foundation) and Phase 2 (Org & Keys): OAuth sign-in (Google, GitHub), sessions, CSRF, users, BYOK Anthropic keys (live-validated, envelope-encrypted), personal API tokens, orgs, members, invites, policy, audit log, GitHub repo listing + inbound webhook, project CRUD and project memory.
- Phase 3 (Templates): setup wizard, template builds (blue/green, SSE build logs), smoke tests.
- Phase 4 (Sessions): preflight (key, budgets, concurrency), sandbox provisioning with live progress, WIP snapshots, idle/max-duration handling, recover, cleanup/orphan jobs, artifacts.
- Phase 5 (Chat & Agent): WebSocket gateway at `/ws` (cookie + Origin or API-token auth, replay from `lastEventId`, Simple/Pro filtering), agent orchestrator around `packages/runner` (turn flow, Output Translation Layer, approvals, budgets, post-turn guardrails with auto-revert), the session screen (chat, preview, Pro diff/files/terminal/timeline/debug tabs), session history and usage analytics + CSV.
- Phase 6 (Review & Delivery): diff, create PR, commit to main, discard, `pull_request` webhook.
- Phase 7 (Power Features): checkpoints before every turn with rewind (code / conversation / both, `/undo`), plan mode (project `OFF`/`AUTO`/`ALWAYS` plus per-message "Plan first") ending in an approve/edit/cancel plan approval, slash commands (built-ins + custom org commands with `$ARGUMENTS`, `@file`, `` !`cmd` ``, a role/mode-filtered palette and Simple quick actions), skills (built-in starter skills, org/project/personal scopes, version history + restore, GitHub import, dry-run), MCP servers (catalog, envelope-encrypted credentials that are never returned, per-tool policy, connection test, graceful degradation with `LSE-MCP-001`), the memory hierarchy (org → repository `LOOSE.md`/`AGENTS.md` → user → session notes, `#` quick-add in Pro, `POST /projects/:id/memory/generate` for a `LOOSE.md` draft), session transcript export, and the UI for all of it (org Extensions page, Pro checkpoints/plan/palette, Simple quick actions and plan checklists without file paths or Markdown).
- Phase 8 (Extensibility): subagents (built-in `code-reviewer`/`test-runner`/`ui-designer`/`researcher` plus org/project/personal ones, Markdown + frontmatter, `@agent-name` delegation, per-subagent cost), hooks on nine lifecycle events with **server-side enforcement** (`command` and built-in handlers run in the sandbox; `http` webhooks are called only by the server behind the SSRF guard with an HMAC-SHA256 `x-loose-signature`, every decision audited as `hook.decision`, `allow`/`deny`/`ask`/`modify`, per-hook fail open/closed, `UserPromptSubmit` evaluated before the turn, post-turn `block_paths` re-validation with auto-revert, one-click recipes and `POST /orgs/:orgId/hooks/:id/test`), plugins (semver manifests bundling skills/commands/subagents/hooks/MCP servers, org-private marketplace, per-project install, update and rollback, conflict reporting with `LSE-EXT-007`), context management (`context_update` usage meter, project `autoCompactPercent`, `PreCompact` hooks, tool-output spill files, cache hit ratio in the usage API), multimodal input (image/PDF attachments, click-to-select element inspection via Playwright, voice dictation in the web composer, before/after screenshots per enabled viewport), and the UI for all of it (six real Extensions tabs, project overrides, Pro context meter and hook timeline, Simple-safe element labels).
- Phase 9 (Platform): scoped-token headless runs with resumable SSE, TypeScript SDK, CLI and GitHub Action; HMAC-signed outbound webhooks with durable retries; GitHub issue-label and PR-comment, Slack, Linear, Jira and cron triggers; fork/resume; shared viewer/co-editor sessions with presence and Pro take-over; and the corresponding Webhooks, Integrations and collaboration UI. The issue-label → sandbox edit → pull-request automation path is covered end to end with the fake sandbox, mock runner and MSW-mocked GitHub API.
- Phase 10 (Hardening & GA): OIDC SSO per org (PKCE + nonce, JWKS-verified ID tokens, verified domains via DNS TXT, JIT provisioning that requires `email_verified` and never merges an IdP subject into an existing account by email, enforce-SSO that also binds PATs and sessions to the org's current connection; SAML behind the off-by-default `sso_saml` flag), TOTP two-step verification with recovery codes and atomic replay protection plus org `requireAdmin2fa`, SCIM 2.0 users/groups with expiring tokens and a write freeze during org deletion, per-org IP allowlists (HTTP and WS), a tamper-evident HMAC hash-chained audit log (cutover marker, `GET /orgs/:orgId/audit-log/verify`, CSV/JSONL export) whose security-sensitive entries are written in the same transaction as the change and fail closed (`LSE-SYS-001`), retention purges, GDPR/DPDP user and org data export and grace-period org deletion, guardrail policy packs, feature flags, S3/MinIO object storage, Prometheus metrics and alert rules, `/readyz` dependency checks, cross-instance WebSocket fan-out and presence over **HMAC-signed** Redis messages, live-socket revocation on logout / PAT deletion / expiry and on org policy changes (SSO replaced/removed, enforce-SSO, admin 2FA, IP allowlist, member removal/role change: a signed `policy_changed` event makes every instance re-check its sockets against the live credential and org policy; a credential re-check that errors closes the socket with retryable `1013` instead of keeping it), a numeric SSRF classifier shared by every outbound guard, CSP/HSTS on the web origin, Dockerfiles and a reference production compose, and the error-code gate (every non-reserved catalog code has an asserting trigger-path test; reserved codes carry a reason in the catalog and are badged on `/docs/errors/:code`).

Phase 7 adds the migration `20261014120000_phase7_power_features` (checkpoints, plans, skills and skill versions, custom commands, MCP servers, memory and session notes), Phase 8 adds `20261015120000_phase8_extensibility` (hook name/failMode/timeout/recipe and last-decision columns, plugin versions and per-project installs, attachment artifacts, project `autoCompactPercent`/`screenshotViewports`, `UsageEvent.subagent`), Phase 9 adds `20261016120000_phase9_platform` (runs, triggers, webhook deliveries, collaborators, session control and fork metadata), and Phase 10 adds six, applied in this order: `20261017120000_phase10_hardening` (SSO connections/identities, domains, SCIM, TOTP/recovery codes, IP allowlist, audit hash chain + immutability trigger, retention, data exports, deletion requests, feature flags), `20261018101500_fix_identity` (PAT `ssoConnectionId`/`mfaVerifiedAt`, `ScimToken.expiresAt` backfilled to +365 days, unique `OrgDomain.verifiedDomain`), `20261018131500_fix_governance_infra` (`AuditChainCutover` marker: unchained audit rows written after the migration ran fail verification) and `20261019001500_audit_insert_guard` (AuditLog insert/update triggers: an unchained row always gets the database clock, so it can never be backdated to look like pre-cutover legacy history; `createdAt`, `orgId` and a row's chain are immutable even in maintenance mode) and `20261019120000_audit_retention_definer` (SECURITY DEFINER retention functions; the runtime role gets no `DELETE` on `AuditLog`, so it can never remove the chain tail, only a marker-announced prefix older than the 30-day minimum) and `20261019180000_audit_redaction_definer` (audit content and chained fields immutable in every mode; `actorId`/`ip` redaction only through the SECURITY DEFINER `loose_audit_redact_user` during a due account deletion, with a signed `audit.redacted` marker that verification requires; the runtime role has no `UPDATE` of audit attribution); run `bun run db:migrate` (production: `prisma migrate deploy` as the owner role, then `docker/postgres/apply-runtime-role.sh`) after pulling them. In production the API and worker must connect as the least-privilege runtime role `loose_app`, not the table owner: an owner can disable those triggers, and only the owner may delete audit rows (see [Database roles](./docs/deployment.md#database-roles); the reference compose does this with its `db-roles` service).

Sandbox providers (`SANDBOX_PROVIDER`):

| Value   | Used for                   | Notes                                                                                        |
| ------- | -------------------------- | -------------------------------------------------------------------------------------------- |
| `e2b`   | production (default there) | needs `E2B_API_KEY`; the server refuses to boot in production without it                     |
| `local` | local demos (dev default)  | **DEV ONLY, no isolation** — see the security note below; refused when `NODE_ENV=production` |
| `fake`  | tests                      | in-memory, scriptable                                                                        |

The agent runs in mock mode (`RUNNER_MOCK=true`, the default unless the provider is `e2b`): a deterministic scripted agent that really edits files but never calls Anthropic. Production runs background jobs in a separate worker (`bun run --cwd apps/server start:worker`); development runs them in-process (`JOBS_INLINE`). A session's runner lives in the API process that serves its WebSocket; since Phase 10 other instances forward that session's commands and events over signed Redis pub/sub, so session affinity is recommended for performance but no longer required (see [`docs/deployment.md`](./docs/deployment.md)).

## Production configuration (Phase 10)

All variables are validated at boot (`apps/server/src/config/env.ts`; names are printed, never values). Full table and rationale: [`docs/deployment.md`](./docs/deployment.md) and `apps/server/.env.example`.

| Variable                                                                                                                                         | Purpose                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TOTP_ISSUER`                                                                                                                                    | Issuer label in authenticator apps (2FA). Default `loose.ai`                                                                                                                                                                                                                                                                                               |
| `SSO_HTTP_TIMEOUT_MS`                                                                                                                            | Timeout for IdP discovery / JWKS / token calls (500–30000, default 5000)                                                                                                                                                                                                                                                                                   |
| `AUDIT_CHAIN_SECRET`                                                                                                                             | HMAC key of the audit hash chain (≥ 32 chars). Derived from `SESSION_SECRET` when unset; set it in production                                                                                                                                                                                                                                              |
| `DELETION_GRACE_DAYS`                                                                                                                            | Grace period before a scheduled org/user deletion runs (0–90, default 30)                                                                                                                                                                                                                                                                                  |
| `DATA_EXPORT_TTL_HOURS`                                                                                                                          | How long a data export stays downloadable (1–720, default 72)                                                                                                                                                                                                                                                                                              |
| `ARTIFACT_STORAGE`                                                                                                                               | `local` (default) or `s3`                                                                                                                                                                                                                                                                                                                                  |
| `S3_BUCKET`, `S3_REGION`, `S3_ENDPOINT`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_FORCE_PATH_STYLE`, `S3_PREFIX`, `S3_SIGNED_URL_TTL_SEC` | S3/MinIO storage. `S3_ENDPOINT` must be `https://` in production and reachable by browsers (presigned links point at it). Links never outlive the export (`min(TTL, 300 s, time left)`)                                                                                                                                                                    |
| `METRICS_TOKEN`                                                                                                                                  | Bearer token for `GET /metrics` on the main port (the route answers 404 while it is unset) and required for a non-loopback secondary listener                                                                                                                                                                                                              |
| `METRICS_PORT`, `METRICS_HOST`                                                                                                                   | Optional secondary metrics listener (binds `127.0.0.1` by default)                                                                                                                                                                                                                                                                                         |
| `TRUST_PROXY`                                                                                                                                    | Reverse-proxy hop count for client IPs (IP allowlists, rate limits, audit)                                                                                                                                                                                                                                                                                 |
| `TRUST_PROXY_HOPS_ACKNOWLEDGED`                                                                                                                  | Production refuses `TRUST_PROXY>0` unless `true`: only set it when the API is reachable exclusively through exactly that many proxies that overwrite `X-Forwarded-For`                                                                                                                                                                                     |
| `FEATURE_FLAGS`                                                                                                                                  | Operator overrides, `flag=on,other=off`. Flags: `sso_oidc`, `sso_saml` (off), `scim`, `admin_2fa`, `ip_allowlist`, `audit_export`, `data_export`, `policy_packs`, `plugins`, `shared_sessions`, `headless_runs` (`policy_packs`, `plugins` and `shared_sessions` can also be overridden per org by an owner). A disabled feature answers `503 LSE-SYS-007` |
| `INSTANCE_ID`                                                                                                                                    | Stable id of an API replica for presence/forwarding (default `<host>-<pid>-<rand>`)                                                                                                                                                                                                                                                                        |
| `READYZ_CHECK_E2B`                                                                                                                               | Include the e2b API in `/readyz` (`e2b: skipped` otherwise)                                                                                                                                                                                                                                                                                                |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                                                                                                                    | Parsed but not wired yet (OpenTelemetry export is a follow-up)                                                                                                                                                                                                                                                                                             |

SSO connections, verified domains, SCIM tokens, 2FA enforcement, IP allowlists and retention windows are configured **per organization** in Org Settings → Security (SSO, domains, SCIM, 2FA, IP allowlist) and → Data (retention, export, deletion), not through environment variables.

API changes to know about when upgrading:

- `DELETE /api/v1/orgs/:orgId` was removed (it deleted a tenant immediately). Organization deletion is only `POST /api/v1/orgs/:orgId/deletion` (owner, browser session, typed slug confirmation, `DELETION_GRACE_DAYS` grace period, cancellable); the old route answers `404`.
- Linear and Jira webhooks moved to per-trigger URLs and secrets (`/api/v1/integrations/{linear,jira}/webhook/<trigger-token>`, see above); the old shared-secret paths answer `401 LSE-AUTH-009`.
- PATs record the assurance of the session that minted them. Once an org enforces SSO or `requireAdmin2fa`, tokens minted outside the org's current SSO connection or before 2FA enrollment are refused until re-issued from a compliant session.

### Deploy, operate, report

- Images: `docker/api.Dockerfile`, `docker/worker.Dockerfile`, `docker/web.Dockerfile` (Nginx with the shared `docker/nginx-security-headers.conf`: CSP, HSTS, XFO, nosniff, Permissions-Policy on every location). Reference single-host stack: [`docker-compose.prod.example.yml`](./docker-compose.prod.example.yml) (needs `S3_ENDPOINT` set to your https S3/MinIO URL). CI/CD: `.github/workflows/{ci,deploy,security,zap-baseline}.yml`.
- Docs index: [`docs/README.md`](./docs/README.md): [deployment](./docs/deployment.md), [SLOs](./docs/slo.md), [incident process](./docs/incident-process.md), [data retention](./docs/privacy/data-retention.md), [SSO setup](./docs/security/sso.md), [threat model](./docs/security/threat-model.md), [Phase 10 security review](./docs/security/review-phase10.md).
- Runbooks per error domain: [SBX](./docs/runbooks/sbx.md), [GH](./docs/runbooks/gh.md), [KEY](./docs/runbooks/key.md), [SYS](./docs/runbooks/sys.md), [AGT](./docs/runbooks/agt.md), [WS](./docs/runbooks/ws.md), [auth & identity](./docs/runbooks/auth-identity.md), [webhooks](./docs/runbooks/webhooks.md).
- Monitoring: [`ops/prometheus/alerts.yml`](./ops/prometheus/alerts.yml) and [`ops/prometheus/README.md`](./ops/prometheus/README.md) (scrape config, metric names). Load-test scripts (staging only): [`loadtest/`](./loadtest/README.md).
- Status page: static [`status/`](./status/README.md) (`index.html` + `status.json`; its inline script/style are pinned by hash in the CSP, so it is excluded from Prettier).
- Vulnerability reports: [`SECURITY.md`](./SECURITY.md) and `/.well-known/security.txt` (served by the web app).
- Error catalog: every `LSE-*` code has a public page at `/docs/errors/:code`. The gate `bunx tsx apps/server/scripts/error-code-gate.ts` (also run as `test/phase10.error-gate.test.ts`) fails when a non-reserved code lacks an asserting trigger-path test.

#### Reserved error codes

14 catalog codes are `reserved` (they carry a `reservedReason` in `packages/shared/src/errorCodes.ts`, are badged on their `/docs/errors/:code` page, and the gate skips them). Three are billing (`LSE-BILL-001..003`, billing is out of scope for GA). The other **11 are product codes reserved pending v1 capabilities that do not exist yet**: nothing in the server can raise them today, so they have no trigger-path test. The spec's "every catalog code has a passing test" exit criterion is therefore met only under this reservation rule; whether to build the capabilities, drop the codes, or accept the reservation for GA is an open product decision.

| Code          | Title                       | Reserved because                                                                      |
| ------------- | --------------------------- | ------------------------------------------------------------------------------------- |
| `LSE-ORG-008` | Seat limit reached          | Seat entitlements are not modeled in v1                                               |
| `LSE-GH-012`  | Repository too large        | Repository/file size limits are not defined or measured in v1                         |
| `LSE-TPL-005` | Invalid settings            | A separate template environment/config schema is not a v1 capability                  |
| `LSE-SBX-006` | Preview unavailable         | Preview reachability is not exposed as a server-side error signal in v1               |
| `LSE-SBX-007` | Workspace out of space      | Sandbox disk telemetry is not available in v1                                         |
| `LSE-SBX-008` | Workspace ran out of memory | Sandbox out-of-memory telemetry is not available in v1                                |
| `LSE-SBX-012` | Website blocked             | Sandbox egress enforcement is not implemented in v1                                   |
| `LSE-SBX-013` | Preview not connected       | A sandbox port-mapping subsystem is not implemented in v1                             |
| `LSE-MCP-005` | Tool response too large     | MCP-specific output validation is not implemented in v1 (generic truncation succeeds) |
| `LSE-MCP-007` | Tool stopped                | MCP stdio process supervision/restart detection is not implemented in v1              |
| `LSE-MCP-009` | Tool service busy           | MCP upstream rate-limit mapping/backoff is not implemented in v1                      |

### Requires staging before GA

These are prepared (scripts, workflows, configs) but deliberately not run locally:

- External penetration test and an OWASP ZAP baseline run (`.github/workflows/zap-baseline.yml`, `workflow_dispatch`, refuses production targets).
- Load tests at spec scale (500 concurrent WebSocket rooms, 100 concurrent sessions) with `loadtest/*.js`.
- SLO measurement against real traffic (session start p95 ≤ 60 s and the other targets in `docs/slo.md`); alerts exist but no SLO has been measured.
- End-to-end runs against real e2b, Anthropic and GitHub (local E2E uses the fake sandbox, mock runner and MSW).
- A real-browser accessibility audit (axe in jsdom skips color contrast, region and scrollable-region checks; keyboard and reflow need a browser) and a browser CSP-violation check of the SPA.
- Infrastructure chaos (Toxiproxy against Postgres/Redis/S3, instance loss); in-process failure injection is covered by `test/phase10.chaos.test.ts`.
- Real multi-instance deployment behind the production proxy, and a real IdP (OIDC) sign-in.

## Local agent demo (no e2b, Anthropic or GitHub)

1. `bun run build` (builds `packages/runner/dist/cli.js` among others).
2. Create a bare repo for the project to clone, e.g. `/tmp/loose-remotes/acme/site.git`, and push a small site to its `main` branch (an `index.html` plus a `server.js` that serves it on `process.env.PORT`).
3. Add to `apps/server/.env`:

   ```bash
   SANDBOX_PROVIDER=local
   RUNNER_MOCK=true
   RUNNER_ENTRY=/absolute/path/to/loose.ai/packages/runner/dist/cli.js
   DEV_GIT_REMOTE_OVERRIDE=/tmp/loose-remotes/{owner}/{repo}.git
   JOBS_INLINE=true
   DEV_LOGIN_ENABLED=true
   LOCAL_SANDBOX_DIR=/tmp/loose-sandboxes   # optional; workspaces live here
   ```

   Remove these lines again when you are done (the remote override points at a temp path).

4. `bun run dev`, sign in with dev login and create an org. The API validates Anthropic keys and GitHub repos live, so without real credentials insert a dummy ACTIVE `ApiKey`, a GitHub `OAuthAccount` and a project for `acme/site` directly in the dev database (encrypted with the server's `EnvelopeCrypto`, as `apps/server/test/sessionHelpers.ts` does). Give the project a startup command that sets the port itself, e.g. `PORT=3000 node server.js`, a public port map entry for 3000 and a health check on `/` port 3000. (A port map entry's optional `envVar` receives that port's preview **URL**, e.g. `VITE_API_URL`; it does not set the listening port.)
5. Build the template from the setup wizard (or `POST …/build-template`), start a session and ask `change "Hello" to "Howdy"`: the preview updates and a change summary appears. Discard works fully offline; create PR pushes to the bare repo but then calls the GitHub API (exercised with mocks in `apps/server/test/e2e.local.test.ts`).

### LocalSandboxProvider (security note)

The `local` provider runs the project's startup commands and the agent runner **directly on your machine** as your user, in a workspace under `LOCAL_SANDBOX_DIR` (default: a temp dir). The command environment is scrubbed and the working directory is confined to the workspace, but there is no process, filesystem or network isolation, and app ports are host ports. Because of that, only one local session per project can run at a time: a session whose app port is already taken fails with `LSE-SBX-004` ("Port … is already in use") instead of previewing the other session's app. Only use it with repositories you trust, never in production, and never with `RUNNER_MOCK=false` against code you have not reviewed.

## Auth design note

The `lucia` and `arctic` npm packages are deprecated, so the server implements Lucia-style sessions directly (random session tokens, only their SHA-256 hash stored, sliding expiry) and hand-rolls the OAuth flows (Google with PKCE, GitHub) using `node:crypto` and `fetch`. Session cookie `loose_session` is HttpOnly, SameSite=Lax and Secure in production. State-changing requests need a signed double-submit CSRF token (`loose_csrf` cookie echoed in `x-csrf-token`); Bearer-token requests and the GitHub webhook are exempt.

## Dev login (security note)

`POST /api/v1/auth/dev-login` signs in as any email without a password, so local development works without OAuth apps. It is mounted only when `NODE_ENV !== 'production'` **and** `DEV_LOGIN_ENABLED=true`; a test asserts the route returns 404 in production even if the flag is set. Never set `DEV_LOGIN_ENABLED=true` on a deployed environment.

# Loose.ai

as of 2nd oct 21:24
kiro-cli --resume-id 0e6d4b68-95df-421d-850f-6d3071292175
