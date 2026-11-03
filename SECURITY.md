# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| Latest `main` branch | ✅ |
| Previous minor | Security fixes only |
| Older | ❌ |

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### Coordinated disclosure

1. **Email** `security@loose.ai` with the subject: `[SECURITY] <brief description>`.
2. Include:
   - A description of the vulnerability and its potential impact.
   - Steps to reproduce (proof-of-concept code, curl commands, screenshots as applicable).
   - Affected component(s) and versions.
   - Any suggested mitigations.
3. Encrypt sensitive details using our PGP key (published at `https://loose.ai/.well-known/security.txt`).

We will:
- Acknowledge receipt within **48 hours**.
- Provide an initial assessment within **5 business days**.
- Keep you informed of our progress and expected fix timeline.
- Credit you in the release notes and advisory (unless you prefer anonymity).

**We do not offer a bug bounty programme at this time**, but we deeply appreciate responsible disclosure.

---

## Security architecture overview

### Authentication

- Sessions use random 32-byte tokens; only their SHA-256 hash is stored (`AuthSession.hash`).
- Sliding expiry; `Secure`, `HttpOnly`, `SameSite=Lax` cookie.
- CSRF: signed double-submit cookie (`x-csrf-token`); exempt for Bearer-token and webhook requests.
- OAuth 2.0 with PKCE (Google and GitHub); state + nonce per request.
- SSO: OIDC (RS256/ES256 ID-token verification with `node:crypto`); SAML deferred (flag `sso_saml` off by default).
- 2FA: TOTP (RFC 6238, SHA-1, 30 s, ±1 step, replay-protected); 10 hashed recovery codes.
- API tokens: scoped personal access tokens; scope checks at every protected endpoint.

### Secrets management

- Anthropic API keys, KMS data keys, SSO client secrets, TOTP secrets and SCIM tokens are all stored as AES-256-GCM envelope-encrypted blobs (`lib/crypto.ts`, `lib/kms.ts`).
- `LOCAL_KMS_MASTER_KEY` (32 bytes, base64): wrap key for the local KMS provider.
- `SESSION_SECRET`: HKDF source for CSRF signing and (as a fallback) the audit chain key.
- Secrets are **never** returned by the API, logged, or included in PR bodies or agent prompts. The test suite enforces this (`test/phase10.secrets.test.ts`).

### Network security

- SSRF guard: all outbound HTTP from hooks, OIDC, MCP, and webhook calls goes through `safeFetch` (`lib/net/safeFetch.ts`), which resolves the hostname once, rejects private/reserved addresses (RFC 1918, RFC 6598, link-local, loopback, multicast, ULA, NAT64-of-private), connects to the pinned IP, and does not follow redirects.
- Content Security Policy, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy set by `middleware/securityHeaders.ts`.

### Sandbox isolation

- Production sandboxes run in e2b (isolated VM per session).
- The `local` sandbox provider runs commands directly on the host; it is refused in production (`NODE_ENV=production`). See README security note.

### Audit log

- Immutable HMAC-SHA256 hash-chained audit log (PostgreSQL trigger + application-level chain).
- Verify integrity: `GET /api/v1/orgs/:orgId/audit-log/verify` (ADMIN).

---

## Security contacts

- **Security email:** security@loose.ai
- **PGP key:** https://loose.ai/.well-known/security.txt

---

## Scope

In-scope for responsible disclosure:
- Authentication and authorization bypass.
- Data exfiltration (cross-tenant access, secrets in API responses).
- SSRF, CSRF, XSS, SQL injection.
- Prompt injection leading to security-relevant outcomes (secret exfiltration, guardrail bypass).
- Insecure direct object references.
- Cryptographic weaknesses in key management.

Out of scope:
- Issues in third-party dependencies not affecting loose.ai directly (report to the dependency maintainer).
- Social engineering.
- Physical attacks.
- Denial of service (we have rate limits; please don't run load tests against production).

---

## Acknowledgements

We thank all security researchers who have responsibly disclosed vulnerabilities to us.
