/**
 * Accessibility smoke tests (spec §17, WCAG 2.1 AA): axe-core over the screens people use most.
 * Each test waits for the screen's real content first, so axe sees the loaded state.
 */
import { defaultOrgPolicy, orgPolicySchema } from '@loose/shared';
import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http } from 'msw';
import { describe, expect, it } from 'vitest';
import { FakeWebSocket } from '@/test/fakeWebSocket';
import {
  api,
  errorResponse,
  list,
  makeAuditEntry,
  makeChainVerify,
  makeDomain,
  makeExport,
  makeMessage,
  makePack,
  makeRetention,
  makeScimToken,
  makeSecurity,
  makeSession,
  makeSessionExtensions,
  makeUser,
  NOW,
  makeSsoConnection,
  ok,
  signedInHandlers,
} from '@/test/fixtures';
import { expectNoA11yViolations, runAxe } from '@/test/axe';
import { server } from '@/test/server';
import { renderRoute } from '@/test/utils';

const signedOut = () => [
  http.get(api('/auth/csrf'), () => ok({ csrfToken: 'csrf-test' })),
  http.get(api('/auth/me'), () => errorResponse('LSE-AUTH-001')),
];

function sessionHandlers(mode: 'SIMPLE' | 'PRO') {
  server.use(...signedInHandlers({ role: 'MEMBER' }));
  server.use(
    http.get(api('/sessions/:id'), () => ok(makeSession({ mode }))),
    http.get(api('/sessions/:id/messages'), () =>
      list([makeMessage({ id: 'u1', content: 'Make the signup button green' })]),
    ),
    http.get(api('/sessions/:id/checkpoints'), () => list([])),
    http.get(api('/sessions/:id/commands'), () => ok(makeSessionExtensions())),
    http.get(api('/orgs/:orgId/subagents'), () => list([])),
    http.get(api('/orgs/:orgId/policy'), () => ok(orgPolicySchema.parse({}))),
  );
}

async function openSocket() {
  await waitFor(() => expect(FakeWebSocket.latest()).toBeDefined());
  act(() => (FakeWebSocket.latest() as FakeWebSocket).open());
  await screen.findByText('Live');
}

describe('axe harness', () => {
  it('actually detects violations (unlabelled input, image without alt, empty button)', async () => {
    const host = document.createElement('div');
    host.innerHTML = '<input type="text"><img src="x.png"><button></button>';
    document.body.append(host);
    try {
      const { violations } = await runAxe(host);
      const ids = violations.map((v) => v.id);
      expect(ids).toEqual(expect.arrayContaining(['label', 'image-alt', 'button-name']));
      await expect(expectNoA11yViolations(host)).rejects.toThrow(/accessibility violation/);
    } finally {
      host.remove();
    }
  });
});

describe('accessibility (axe, WCAG 2.1 A/AA)', () => {
  it('sign-in', async () => {
    server.use(...signedOut());
    const { container } = renderRoute('/signin');
    await screen.findByTestId('sso-signin');
    await expectNoA11yViolations(container);
  });

  it('sign-in with an SSO result and an inline error', async () => {
    server.use(
      ...signedOut(),
      http.get(api('/auth/sso/discover'), () =>
        ok({
          sso: true,
          orgSlug: 'acme',
          orgName: 'Acme',
          protocol: 'OIDC',
          enforced: false,
          startUrl: '/api/v1/auth/sso/acme/start',
        }),
      ),
    );
    const { container } = renderRoute('/signin');
    const form = await screen.findByTestId('sso-signin');
    await userEvent.type(form.querySelector('input') as HTMLInputElement, 'ada@acme.com');
    await userEvent.click(screen.getByRole('button', { name: /continue with sso/i }));
    await screen.findByRole('link', { name: /sign in with acme/i });
    await expectNoA11yViolations(container);
  });

  it('two-step sign-in challenge', async () => {
    server.use(...signedInHandlers());
    server.use(
      http.get(api('/auth/me'), () => ok(makeUser({ twoFactorEnabled: true, mfaRequired: true }))),
      http.get(api('/users/me/2fa'), () =>
        ok({
          enabled: true,
          enabledAt: NOW,
          pendingEnrollment: false,
          recoveryCodesRemaining: 10,
          requiredByOrg: false,
        }),
      ),
    );
    const { container } = renderRoute('/auth/2fa?returnTo=%2Forgs%2Forg_1');
    await screen.findByLabelText(/authentication code/i);
    await expectNoA11yViolations(container);
  });

  it('two-step enrolment (QR, setup key) and the one-time recovery codes', async () => {
    server.use(...signedInHandlers());
    server.use(
      http.get(api('/users/me/2fa'), () =>
        ok({
          enabled: false,
          enabledAt: null,
          pendingEnrollment: false,
          recoveryCodesRemaining: 0,
          requiredByOrg: true,
        }),
      ),
      http.post(api('/users/me/2fa/enroll'), () =>
        ok({
          secret: 'JBSWY3DPEHPK3PXP',
          otpauthUrl:
            'otpauth://totp/loose.ai:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=loose.ai',
        }),
      ),
      http.post(api('/users/me/2fa/activate'), () =>
        ok({ recoveryCodes: ['aaaaa-22222', 'bbbbb-33333', 'ccccc-44444'] }),
      ),
    );
    const { container } = renderRoute('/auth/2fa');
    await screen.findByRole('img', { name: /qr code/i });
    await expectNoA11yViolations(container);
    await userEvent.type(screen.getByLabelText(/enter the 6-digit code to confirm/i), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Turn on' }));
    await screen.findByTestId('recovery-codes');
    await expectNoA11yViolations(container);
  });

  it('dashboard (admin)', async () => {
    server.use(...signedInHandlers({ role: 'ADMIN' }));
    const { container } = renderRoute('/orgs/org_1');
    await screen.findByRole('article', { name: 'Storefront' });
    await expectNoA11yViolations(container);
  });

  it('session — Simple mode', async () => {
    sessionHandlers('SIMPLE');
    const { container } = renderRoute('/session/sess_1');
    await openSocket();
    await screen.findByText('Make the signup button green');
    await expectNoA11yViolations(container);
  });

  it('session — Pro mode', async () => {
    sessionHandlers('PRO');
    server.use(http.get(api('/sessions/:id/diff'), () => ok({ files: [] })));
    const { container } = renderRoute('/session/sess_1');
    await openSocket();
    await screen.findByRole('tab', { name: 'Diff' });
    await expectNoA11yViolations(container);
  });

  it('account settings (2FA + privacy sections)', async () => {
    server.use(
      ...signedInHandlers(),
      http.get(api('/users/me/memory'), () => ok({ memory: null, updatedAt: null })),
      http.get(api('/users/me/mcp-servers'), () => list([])),
    );
    const { container } = renderRoute('/settings');
    await screen.findByRole('heading', { name: /two-step verification|two-factor/i });
    await expectNoA11yViolations(container);
  });

  it('organization settings', async () => {
    server.use(
      ...signedInHandlers({ role: 'OWNER' }),
      http.get(api('/orgs/:orgId/members'), () => list([])),
      http.get(api('/orgs/:orgId/invites'), () => list([])),
      http.get(api('/orgs/:orgId/policy'), () => ok(defaultOrgPolicy())),
    );
    const { container } = renderRoute('/orgs/org_1/settings');
    await screen.findByRole('tab', { name: /members/i });
    await expectNoA11yViolations(container);
  });

  it('audit log', async () => {
    server.use(
      ...signedInHandlers({ role: 'ADMIN' }),
      http.get(api('/orgs/:orgId/members'), () => list([])),
      http.get(api('/orgs/:orgId/audit-log'), () => list([makeAuditEntry()])),
      http.get(api('/orgs/:orgId/audit-log/verify'), () => ok(makeChainVerify())),
    );
    const { container } = renderRoute('/orgs/org_1/audit');
    await screen.findByRole('table');
    await expectNoA11yViolations(container);
  });

  it('security settings (SSO, domains, SCIM, access)', async () => {
    server.use(
      ...signedInHandlers({ role: 'OWNER' }),
      http.get(api('/orgs/:orgId/identity/sso'), () => ok(makeSsoConnection())),
      http.get(api('/orgs/:orgId/identity/domains'), () => list([makeDomain()])),
      http.get(api('/orgs/:orgId/identity/scim-tokens'), () => list([makeScimToken()])),
      http.get(api('/orgs/:orgId/identity/security'), () => ok(makeSecurity())),
    );
    const { container } = renderRoute('/orgs/org_1/settings/security');
    await screen.findAllByText('acme.com');
    await expectNoA11yViolations(container);
  });

  it('data settings (retention, export, deletion)', async () => {
    server.use(
      ...signedInHandlers({ role: 'OWNER' }),
      http.get(api('/orgs/:orgId/retention'), () => ok(makeRetention())),
      http.get(api('/orgs/:orgId/data-exports'), () => list([makeExport()])),
      http.get(api('/orgs/:orgId/deletion'), () => ok(null)),
    );
    const { container } = renderRoute('/orgs/org_1/settings/data');
    await screen.findByRole('list', { name: /exports/i });
    await expectNoA11yViolations(container);
  });

  it('policy packs', async () => {
    server.use(
      ...signedInHandlers({ role: 'ADMIN' }),
      http.get(api('/orgs/:orgId/policy-packs'), () => list([makePack()])),
    );
    const { container } = renderRoute('/orgs/org_1/policy-packs');
    await screen.findByTestId('pack-no-infra');
    await expectNoA11yViolations(container);
  });

  it('public error docs (index and detail)', async () => {
    server.use(...signedOut());
    const index = renderRoute('/docs/errors');
    await screen.findByRole('heading', { level: 1 });
    await expectNoA11yViolations(index.container);
    index.unmount();
    const detail = renderRoute('/docs/errors/LSE-AUTH-010');
    await screen.findByText('LSE-AUTH-010');
    await expectNoA11yViolations(detail.container);
  });
});
