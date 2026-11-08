/**
 * AuthZ expectations table (Phase 10 §7.1, W4). One entry per `METHOD path` the route inventory
 * can produce (see `routeInventory.ts`). `test/phase10.authz-matrix.test.ts` fails when a live
 * route has no entry here, or when an entry here matches no live route (so the table can never
 * silently drift from the app).
 *
 * `auth`:
 *  - 'public'      — no authentication at all (incl. webhooks verified by their own signature)
 *  - 'session'     — requireAuth(ctx) default: cookie session OR bearer API token both work
 *  - 'session-only'— requireAuth(ctx, { allowToken: false }): cookie session only, token → 401 LSE-AUTH-001
 *  - 'org'         — like 'session' but additionally behind requireOrg(ctx) (needs `minRole`)
 *  - 'org-session-only' — org-scoped AND session-only (webhooks/triggers/policy admin UX)
 *  - 'scim'        — SCIM bearer token (not cookie/CSRF); not yet enumerable as a route (§ below)
 *  - 'signature'   — verified by an HMAC/webhook signature, not a session or token
 *  - 'metrics'     — Bearer METRICS_TOKEN on the main port
 *
 * `minRole` (org routes only) is the lowest `Role` (`VIEWER < MEMBER < ADMIN < OWNER`) that may
 * call the route; the matrix asserts a member below it gets 403 `LSE-ORG-002` and a non-member
 * gets 403/404 `LSE-ORG-001`.
 *
 * `pendingOwner` marks a route whose current handler is still the Phase 10 stub (503
 * `LSE-SYS-007`) — the role gate in front of the stub is already final (per phase10-design.md
 * §11), so the matrix still asserts auth/role behaviour for these, it just also tolerates the 503
 * body on the "should succeed" case instead of the route's real 2xx.
 */
export type AuthKind =
  | 'public'
  | 'session'
  | 'session-only'
  | 'org'
  | 'org-session-only'
  | 'scim'
  | 'signature'
  | 'metrics';

export type OrgRole = 'VIEWER' | 'MEMBER' | 'ADMIN' | 'OWNER';

export interface RouteExpectation {
  auth: AuthKind;
  minRole?: OrgRole;
  /** Still answers the Phase 10 503 stub; owning workstream listed for traceability only. */
  pendingOwner?: 'W1' | 'W2' | 'W3';
  /** Free-text note for humans reading a failure diff. */
  note?: string;
}

function org(minRole: OrgRole, extra: Partial<RouteExpectation> = {}): RouteExpectation {
  return { auth: 'org', minRole, ...extra };
}
function orgSessionOnly(minRole: OrgRole, extra: Partial<RouteExpectation> = {}): RouteExpectation {
  return { auth: 'org-session-only', minRole, ...extra };
}

export const AUTHZ_EXPECTATIONS: Record<string, RouteExpectation> = {
  // ---- health / metrics ------------------------------------------------------------
  'GET /healthz': { auth: 'public' },
  'GET /readyz': { auth: 'public' },
  'GET /metrics': {
    auth: 'metrics',
    note: '404 LSE-NF-001 until METRICS_TOKEN is set (foundation/W3)',
  },

  // ---- feature flags (public / org) ------------------------------------------------
  'GET /api/v1/feature-flags': { auth: 'public' },
  'GET /api/v1/orgs/:orgId/feature-flags': org('VIEWER'),
  'PUT /api/v1/orgs/:orgId/feature-flags': org('OWNER', {
    note: 'session-only in-handler (not CSRF-exempt token)',
  }),

  // ---- auth (session bootstrap; mostly public by design) ---------------------------
  'GET /api/v1/auth/csrf': { auth: 'public' },
  'GET /api/v1/auth/me': { auth: 'session' },
  'GET /api/v1/auth/sessions': { auth: 'session-only' },
  'POST /api/v1/auth/logout': { auth: 'public', note: 'no-op without a session; clears cookie' },
  'POST /api/v1/auth/logout-all': { auth: 'session-only' },
  'POST /api/v1/auth/dev-login': { auth: 'public', note: 'mounted only outside production' },
  'GET /api/v1/auth/:provider': { auth: 'public', note: 'redirects to the OAuth provider' },
  'GET /api/v1/auth/:provider/callback': {
    auth: 'public',
    note: 'OAuth callback; validates state/PKCE itself',
  },

  // ---- identity: SSO / 2FA (W1, implemented) -----------------------------------------
  'GET /api/v1/auth/sso/discover': { auth: 'public' },
  'GET /api/v1/auth/sso/:orgSlug/start': {
    auth: 'public',
    note: 'requires sso_oidc flag; redirects to the IdP',
  },
  'GET /api/v1/auth/sso/:orgSlug/callback': {
    auth: 'public',
    note: 'requires sso_oidc flag; validates state/nonce/PKCE itself',
  },
  'POST /api/v1/auth/sso/:orgSlug/saml/acs': {
    auth: 'public',
    note: 'SAML; sso_saml flag off → 503 LSE-SYS-007',
  },
  'POST /api/v1/auth/2fa/verify': { auth: 'session-only' },
  'GET /api/v1/users/me/2fa': { auth: 'session-only' },
  'POST /api/v1/users/me/2fa/enroll': { auth: 'session-only' },
  'POST /api/v1/users/me/2fa/activate': { auth: 'session-only' },
  'POST /api/v1/users/me/2fa/disable': { auth: 'session-only' },
  'POST /api/v1/users/me/2fa/recovery-codes': { auth: 'session-only' },

  // ---- governance: privacy (W2, implemented) ------------------------------------------
  'POST /api/v1/users/me/privacy/exports': { auth: 'session-only' },
  'GET /api/v1/users/me/privacy/exports': { auth: 'session-only' },
  'GET /api/v1/users/me/privacy/exports/:id': { auth: 'session-only' },
  'GET /api/v1/users/me/privacy/exports/:id/download': { auth: 'session-only' },
  'GET /api/v1/users/me/privacy/deletion': { auth: 'session-only' },
  'POST /api/v1/users/me/privacy/deletion': { auth: 'session-only' },
  'DELETE /api/v1/users/me/privacy/deletion': { auth: 'session-only' },

  // ---- users/me (profile, BYOK keys, personal tokens) --------------------------------
  'GET /api/v1/users/me': { auth: 'session' },
  'PUT /api/v1/users/me': { auth: 'session-only' },
  'GET /api/v1/users/me/memory': { auth: 'session-only' },
  'PUT /api/v1/users/me/memory': { auth: 'session-only' },
  'GET /api/v1/users/me/mcp-servers': { auth: 'session-only' },
  'GET /api/v1/users/me/api-keys': { auth: 'session-only' },
  'POST /api/v1/users/me/api-keys': { auth: 'session-only' },
  'POST /api/v1/users/me/api-keys/:id/revalidate': { auth: 'session-only' },
  'DELETE /api/v1/users/me/api-keys/:id': { auth: 'session-only' },
  'GET /api/v1/users/me/tokens': { auth: 'session-only' },
  'POST /api/v1/users/me/tokens': { auth: 'session-only' },
  'DELETE /api/v1/users/me/tokens/:id': { auth: 'session-only' },

  // ---- orgs: top-level ----------------------------------------------------------------
  'GET /api/v1/orgs/invites/:token': { auth: 'public', note: 'invite preview by token' },
  'POST /api/v1/orgs/invites/:token/accept': { auth: 'session-only' },
  'POST /api/v1/orgs': { auth: 'session-only' },
  'GET /api/v1/orgs': { auth: 'session' },

  // ---- orgs: org-scoped core -----------------------------------------------------------
  'GET /api/v1/orgs/:orgId': org('VIEWER'),
  'PUT /api/v1/orgs/:orgId': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/members': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/members/:userId': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/members/:userId': org('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/members/:userId': org('VIEWER', {
    note: 'any member may remove themselves; ADMIN+ to remove someone else (checked in-handler)',
  }),
  'POST /api/v1/orgs/:orgId/invites': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/invites': org('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/invites/:inviteId': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/policy': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/policy': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/audit-log': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/sessions': org('MEMBER'),
  'GET /api/v1/orgs/:orgId/usage': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/memory': org('MEMBER'),
  'PUT /api/v1/orgs/:orgId/memory': org('ADMIN'),

  // ---- identity: org admin (W1, implemented; ADMIN+session-only via sessionOnlyGuard) ---
  'GET /api/v1/orgs/:orgId/identity/sso': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/identity/sso': org('OWNER'),
  'DELETE /api/v1/orgs/:orgId/identity/sso': org('OWNER'),
  'POST /api/v1/orgs/:orgId/identity/sso/test': org('OWNER'),
  'GET /api/v1/orgs/:orgId/identity/domains': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/identity/domains': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/identity/domains/:id/verify': org('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/identity/domains/:id': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/identity/scim-tokens': org('OWNER'),
  'POST /api/v1/orgs/:orgId/identity/scim-tokens': org('OWNER'),
  'DELETE /api/v1/orgs/:orgId/identity/scim-tokens/:id': org('OWNER'),
  'GET /api/v1/orgs/:orgId/identity/security': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/identity/security': org('OWNER'),

  // ---- governance: org admin (W2, implemented) -------------------------------------------
  'GET /api/v1/orgs/:orgId/audit-log/export': org('ADMIN', {
    note: 'session-only + audit_export flag',
  }),
  'GET /api/v1/orgs/:orgId/audit-log/verify': org('ADMIN', { note: 'audit_export flag' }),
  'GET /api/v1/orgs/:orgId/retention': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/retention': org('OWNER', { note: 'session-only' }),
  'POST /api/v1/orgs/:orgId/data-exports': org('OWNER', {
    note: 'session-only + data_export flag',
  }),
  'GET /api/v1/orgs/:orgId/data-exports': org('OWNER', { note: 'data_export flag' }),
  'GET /api/v1/orgs/:orgId/data-exports/:id': org('OWNER', { note: 'data_export flag' }),
  'GET /api/v1/orgs/:orgId/data-exports/:id/download': org('OWNER', { note: 'data_export flag' }),
  'GET /api/v1/orgs/:orgId/deletion': org('OWNER', { note: 'session-only' }),
  'POST /api/v1/orgs/:orgId/deletion': org('OWNER', { note: 'session-only' }),
  'DELETE /api/v1/orgs/:orgId/deletion': org('OWNER', { note: 'session-only' }),
  'GET /api/v1/orgs/:orgId/policy-packs': org('ADMIN', { note: 'policy_packs flag' }),
  'POST /api/v1/orgs/:orgId/policy-packs': org('ADMIN', {
    note: 'session-only + policy_packs flag',
  }),
  'GET /api/v1/orgs/:orgId/policy-packs/:packId': org('ADMIN', { note: 'policy_packs flag' }),
  'PUT /api/v1/orgs/:orgId/policy-packs/:packId': org('ADMIN', {
    note: 'session-only + policy_packs flag',
  }),
  'DELETE /api/v1/orgs/:orgId/policy-packs/:packId': org('ADMIN', {
    note: 'session-only + policy_packs flag',
  }),
  'POST /api/v1/orgs/:orgId/policy-packs/:packId/apply': org('ADMIN', {
    note: 'session-only + policy_packs flag',
  }),

  // ---- extensions: skills / commands / mcp / subagents / hooks / plugins (MEMBER view, ADMIN write) --
  'GET /api/v1/orgs/:orgId/skills': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/skills': org('MEMBER', {
    note: 'personal (USER) skills allowed at MEMBER; service checks ownership for shared scopes',
  }),
  'POST /api/v1/orgs/:orgId/skills/dry-run': org('MEMBER'),
  'GET /api/v1/orgs/:orgId/skills/:id': org('MEMBER'),
  'PUT /api/v1/orgs/:orgId/skills/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'DELETE /api/v1/orgs/:orgId/skills/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'GET /api/v1/orgs/:orgId/skills/:id/versions': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/skills/:id/versions/:version/restore': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'POST /api/v1/orgs/:orgId/skills/:id/dry-run': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/skills/import': org('MEMBER'),
  'GET /api/v1/orgs/:orgId/commands': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/commands': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'PUT /api/v1/orgs/:orgId/commands/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'DELETE /api/v1/orgs/:orgId/commands/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'GET /api/v1/orgs/:orgId/mcp-catalog': org('MEMBER'),
  'GET /api/v1/orgs/:orgId/mcp-servers': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/mcp-servers': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'GET /api/v1/orgs/:orgId/mcp-servers/:id': org('MEMBER'),
  'PUT /api/v1/orgs/:orgId/mcp-servers/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'DELETE /api/v1/orgs/:orgId/mcp-servers/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'POST /api/v1/orgs/:orgId/mcp-servers/:id/test': org('MEMBER'),
  'GET /api/v1/orgs/:orgId/subagents': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/subagents': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'GET /api/v1/orgs/:orgId/subagents/:id': org('MEMBER'),
  'PUT /api/v1/orgs/:orgId/subagents/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'DELETE /api/v1/orgs/:orgId/subagents/:id': org('MEMBER', {
    note: 'ownership/scope checked in-handler',
  }),
  'GET /api/v1/orgs/:orgId/hooks/recipes': org('MEMBER'),
  'GET /api/v1/orgs/:orgId/hooks': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/hooks': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/hooks/:id': org('MEMBER'),
  'PUT /api/v1/orgs/:orgId/hooks/:id': org('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/hooks/:id': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/hooks/:id/test': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/plugins': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/plugins': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/plugins/validate': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/plugins/:id': org('MEMBER'),
  'DELETE /api/v1/orgs/:orgId/plugins/:id': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/plugins/:id/versions': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/plugins/:id/install': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/plugins/:id/install': org('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/plugins/:id/install': org('ADMIN'),

  // ---- webhooks / triggers (ADMIN, session-only) -----------------------------------------
  'GET /api/v1/orgs/:orgId/webhooks': orgSessionOnly('ADMIN'),
  'POST /api/v1/orgs/:orgId/webhooks': orgSessionOnly('ADMIN'),
  'GET /api/v1/orgs/:orgId/webhooks/:id': orgSessionOnly('ADMIN'),
  'PUT /api/v1/orgs/:orgId/webhooks/:id': orgSessionOnly('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/webhooks/:id': orgSessionOnly('ADMIN'),
  'POST /api/v1/orgs/:orgId/webhooks/:id/rotate-secret': orgSessionOnly('ADMIN'),
  'POST /api/v1/orgs/:orgId/webhooks/:id/test': orgSessionOnly('ADMIN'),
  'GET /api/v1/orgs/:orgId/webhooks/:id/deliveries': orgSessionOnly('ADMIN'),
  'GET /api/v1/orgs/:orgId/webhooks/:id/deliveries/:deliveryId': orgSessionOnly('ADMIN'),
  'POST /api/v1/orgs/:orgId/webhooks/:id/deliveries/:deliveryId/redeliver': orgSessionOnly('ADMIN'),
  'GET /api/v1/orgs/:orgId/triggers': orgSessionOnly('ADMIN'),
  'POST /api/v1/orgs/:orgId/triggers': orgSessionOnly('ADMIN'),
  'GET /api/v1/orgs/:orgId/triggers/:id': orgSessionOnly('ADMIN'),
  'PUT /api/v1/orgs/:orgId/triggers/:id': orgSessionOnly('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/triggers/:id': orgSessionOnly('ADMIN'),
  'POST /api/v1/orgs/:orgId/triggers/:id/fire': orgSessionOnly('ADMIN'),
  'GET /api/v1/orgs/:orgId/triggers/:id/runs': orgSessionOnly('ADMIN'),

  // ---- projects -----------------------------------------------------------------------------
  'GET /api/v1/orgs/:orgId/projects': org('VIEWER'),
  'POST /api/v1/orgs/:orgId/projects': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/projects/:projectId': org('VIEWER'),
  'PUT /api/v1/orgs/:orgId/projects/:projectId': org('ADMIN'),
  'DELETE /api/v1/orgs/:orgId/projects/:projectId': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/projects/:projectId/memory': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/projects/:projectId/memory': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/projects/:projectId/build-template': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/projects/:projectId/template-status': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/projects/:projectId/template-logs': org('ADMIN'),
  'POST /api/v1/orgs/:orgId/projects/:projectId/smoke-test': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/projects/:projectId/active-sessions': org('MEMBER'),
  'POST /api/v1/orgs/:orgId/projects/:projectId/memory/generate': org('ADMIN'),
  'GET /api/v1/orgs/:orgId/projects/:projectId/extensions': org('ADMIN'),
  'PUT /api/v1/orgs/:orgId/projects/:projectId/extensions': org('ADMIN'),

  // ---- github -------------------------------------------------------------------------------
  'GET /api/v1/github/repos': { auth: 'session' },
  'GET /api/v1/github/repos/:owner/:repo': { auth: 'session' },
  'POST /api/v1/github/webhook': { auth: 'signature', note: 'x-hub-signature-256, raw body' },

  // ---- integrations (Slack / Linear / Jira) --------------------------------------------------
  'POST /api/v1/integrations/slack/commands': {
    auth: 'signature',
    note: 'Slack HMAC; 503 LSE-SYS-007 w/o secret',
  },
  'POST /api/v1/integrations/linear/webhook': {
    auth: 'signature',
    note: 'legacy global path; 401 LSE-AUTH-009 (P10-SEC-007)',
  },
  'POST /api/v1/integrations/linear/webhook/:token': {
    auth: 'signature',
    note: 'per-trigger token + per-trigger HMAC (P10-SEC-007)',
  },
  'POST /api/v1/integrations/jira/webhook': {
    auth: 'signature',
    note: 'legacy global path; 401 LSE-AUTH-009 (P10-SEC-007)',
  },
  'POST /api/v1/integrations/jira/webhook/:token': {
    auth: 'signature',
    note: 'per-trigger token + per-trigger HMAC (P10-SEC-007)',
  },

  // ---- public artifacts -----------------------------------------------------------------------
  'GET /api/v1/public-artifacts/:token': { auth: 'public', note: 'signed, expiring token' },

  // ---- sessions (participant: owner or org ADMIN+; token needs sessions:read/write) ------------
  'POST /api/v1/sessions': {
    auth: 'session',
    note: 'participant model; scope sessions:write for tokens',
  },
  'GET /api/v1/sessions/:id': { auth: 'session' },
  'POST /api/v1/sessions/:id/recover': { auth: 'session' },
  'POST /api/v1/sessions/:id/fork': { auth: 'session' },
  'POST /api/v1/sessions/:id/resume': { auth: 'session' },
  'POST /api/v1/sessions/:id/share': { auth: 'session' },
  'GET /api/v1/sessions/:id/collaborators': { auth: 'session' },
  'DELETE /api/v1/sessions/:id/share/:userId': { auth: 'session' },
  'POST /api/v1/sessions/:id/take-over': { auth: 'session' },
  'POST /api/v1/sessions/:id/release': { auth: 'session' },
  'GET /api/v1/sessions/:id/artifacts': { auth: 'session' },
  'GET /api/v1/sessions/:id/artifacts/:artifactId/content': { auth: 'session' },
  'GET /api/v1/sessions/:id/messages': { auth: 'session' },
  'POST /api/v1/sessions/:id/messages': { auth: 'session' },
  'POST /api/v1/sessions/:id/interrupt': { auth: 'session' },
  'GET /api/v1/sessions/:id/approvals': { auth: 'session' },
  'POST /api/v1/sessions/:id/approvals/:approvalId': { auth: 'session' },
  'GET /api/v1/sessions/:id/checkpoints': { auth: 'session' },
  'POST /api/v1/sessions/:id/checkpoints/:checkpointId/rewind': { auth: 'session' },
  'GET /api/v1/sessions/:id/commands': { auth: 'session' },
  'POST /api/v1/sessions/:id/commands': { auth: 'session' },
  'GET /api/v1/sessions/:id/notes': { auth: 'session' },
  'PUT /api/v1/sessions/:id/notes': { auth: 'session' },
  'POST /api/v1/sessions/:id/notes': { auth: 'session' },
  'GET /api/v1/sessions/:id/transcript': { auth: 'session' },
  'POST /api/v1/sessions/:id/attachments': { auth: 'session' },
  'POST /api/v1/sessions/:id/inspect': { auth: 'session' },
  'GET /api/v1/sessions/:id/diff': { auth: 'session' },
  'POST /api/v1/sessions/:id/create-pr': { auth: 'session' },
  'POST /api/v1/sessions/:id/commit-to-main': { auth: 'session' },
  'POST /api/v1/sessions/:id/discard': { auth: 'session' },

  // ---- runs (headless; scoped tokens runs:read/runs:write) --------------------------------------
  'POST /api/v1/runs': { auth: 'session', note: 'requireScope runs:write for tokens' },
  'GET /api/v1/runs': { auth: 'session', note: 'requireScope runs:read for tokens' },
  'GET /api/v1/runs/:id': { auth: 'session', note: 'requireScope runs:read for tokens' },
  'POST /api/v1/runs/:id/cancel': { auth: 'session', note: 'requireScope runs:write for tokens' },
  'GET /api/v1/runs/:id/events': {
    auth: 'session',
    note: 'requireScope runs:read for tokens; SSE',
  },

  // ---- SCIM 2.0 (W1, implemented): bearer `loose_scim_…` tokens, mounted before cookies/CSRF ----
  'GET /api/v1/scim/v2/ServiceProviderConfig': { auth: 'scim' },
  'GET /api/v1/scim/v2/ResourceTypes': { auth: 'scim' },
  'GET /api/v1/scim/v2/Schemas': { auth: 'scim' },
  'GET /api/v1/scim/v2/Users': { auth: 'scim' },
  'POST /api/v1/scim/v2/Users': { auth: 'scim' },
  'GET /api/v1/scim/v2/Users/:id': { auth: 'scim' },
  'PUT /api/v1/scim/v2/Users/:id': { auth: 'scim' },
  'PATCH /api/v1/scim/v2/Users/:id': { auth: 'scim' },
  'DELETE /api/v1/scim/v2/Users/:id': { auth: 'scim' },
  'GET /api/v1/scim/v2/Groups': { auth: 'scim' },
  'POST /api/v1/scim/v2/Groups': { auth: 'scim' },
  'GET /api/v1/scim/v2/Groups/:id': { auth: 'scim' },
  'PUT /api/v1/scim/v2/Groups/:id': { auth: 'scim' },
  'PATCH /api/v1/scim/v2/Groups/:id': { auth: 'scim' },
  'DELETE /api/v1/scim/v2/Groups/:id': { auth: 'scim' },
};

export const SCIM_MOUNT_PREFIX = '/api/v1/scim/v2';
