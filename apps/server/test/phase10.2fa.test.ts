/**
 * Phase 10 / W1 — two-step verification (TOTP + recovery codes, spec §8.20):
 * enrollment, activation, the per-session challenge (LSE-AUTH-012), code replay and lockout
 * (LSE-AUTH-010 / LSE-AUTH-008), recovery codes, disable, and the org-wide `requireAdmin2fa`
 * enforcement for OWNER/ADMIN.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { API_PREFIX, RECOVERY_CODE_COUNT, TOTP_PERIOD_SEC } from '@loose/shared';
import {
  base32Decode,
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCode,
  otpauthUrl,
  totpCode,
  totpStep,
  verifyTotp,
} from '../src/services/identity/totp';
import { TWO_FACTOR_MAX_FAILURES } from '../src/services/identity/twoFactor.service';
import {
  addMember,
  createOrg,
  expectError,
  login,
  makeApp,
  resetDb,
  testPrisma,
  type Client,
} from './helpers';

const prisma = testPrisma();
const { app, ctx } = makeApp();

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await resetDb(prisma);
});

const twoFa = (path = '') => `${API_PREFIX}/users/me/2fa${path}`;

interface Enrolled {
  secret: Buffer;
  recoveryCodes: string[];
}

async function enroll(client: Client): Promise<Enrolled> {
  const started = await client.post(twoFa('/enroll'));
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const secret = base32Decode(started.body.data.secret as string);
  expect(secret).not.toBeNull();
  const activated = await client.post(twoFa('/activate'), {
    code: totpCode(secret as Buffer, totpStep()),
  });
  expect(activated.status, JSON.stringify(activated.body)).toBe(200);
  return {
    secret: secret as Buffer,
    recoveryCodes: activated.body.data.recoveryCodes as string[],
  };
}

/** A code for a step the user has not consumed yet (the window allows current ± 1). */
function nextCode(secret: Buffer): string {
  return totpCode(secret, totpStep() + 1);
}

// ---------------------------------------------------------------------------------------------

describe('TOTP primitives', () => {
  it('matches RFC 6238 test vectors for SHA-1', () => {
    // RFC 6238 appendix B uses the ASCII secret "12345678901234567890".
    const secret = Buffer.from('12345678901234567890', 'ascii');
    const at = (unixSeconds: number) => totpCode(secret, Math.floor(unixSeconds / TOTP_PERIOD_SEC));
    expect(at(59)).toBe('287082');
    expect(at(1111111109)).toBe('081804');
    expect(at(1111111111)).toBe('050471');
    expect(at(1234567890)).toBe('005924');
    expect(at(2000000000)).toBe('279037');
  });

  it('accepts ±1 step, rejects replays and malformed codes', () => {
    const secret = Buffer.from('12345678901234567890', 'ascii');
    const step = totpStep();
    expect(verifyTotp(secret, totpCode(secret, step)).ok).toBe(true);
    expect(verifyTotp(secret, totpCode(secret, step - 1)).ok).toBe(true);
    expect(verifyTotp(secret, totpCode(secret, step + 1)).ok).toBe(true);
    expect(verifyTotp(secret, totpCode(secret, step + 2)).ok).toBe(false);
    expect(verifyTotp(secret, '12345').ok).toBe(false);
    expect(verifyTotp(secret, 'abcdef').ok).toBe(false);
    const replay = verifyTotp(secret, totpCode(secret, step), { lastStep: step });
    expect(replay).toMatchObject({ ok: false, replayed: true });
    expect(verifyTotp(secret, totpCode(secret, step + 1), { lastStep: step }).ok).toBe(true);
  });

  it('round-trips base32 and builds an otpauth URL', () => {
    const secret = Buffer.from('12345678901234567890', 'ascii');
    const url = new URL(otpauthUrl({ issuer: 'loose.ai', account: 'a@b.test', secret }));
    expect(url.protocol).toBe('otpauth:');
    expect(url.pathname).toContain('loose.ai:a%40b.test');
    const encoded = url.searchParams.get('secret') as string;
    expect(base32Decode(encoded)?.equals(secret)).toBe(true);
    expect(base32Decode('not base32!')).toBeNull();
  });

  it('generates distinct single-use recovery codes with stable hashes', () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    expect(new Set(codes).size).toBe(RECOVERY_CODE_COUNT);
    for (const code of codes) expect(code).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
    const code = codes[0] as string;
    expect(normalizeRecoveryCode(` ${code.toUpperCase()} `)).toBe(code.replace('-', ''));
    expect(hashRecoveryCode(code)).toBe(hashRecoveryCode(code.toUpperCase().replace('-', '')));
    expect(hashRecoveryCode(code)).not.toBe(hashRecoveryCode(codes[1] as string));
  });
});

describe('enrollment', () => {
  it('enrolls, activates and shows recovery codes exactly once', async () => {
    const client = await login(app);
    const before = await client.get(twoFa());
    expect(before.status).toBe(200);
    expect(before.body.data).toMatchObject({
      enabled: false,
      pendingEnrollment: false,
      recoveryCodesRemaining: 0,
      requiredByOrg: false,
    });

    const started = await client.post(twoFa('/enroll'));
    expect(started.body.data.secret).toMatch(/^[A-Z2-7]+$/);
    expect(started.body.data.otpauthUrl).toContain('otpauth://totp/loose.ai:');
    const pending = await client.get(twoFa());
    expect(pending.body.data).toMatchObject({ enabled: false, pendingEnrollment: true });

    const secret = base32Decode(started.body.data.secret as string) as Buffer;
    expectError(await client.post(twoFa('/activate'), { code: '000000' }), 'LSE-AUTH-010', 401);

    const activated = await client.post(twoFa('/activate'), { code: totpCode(secret, totpStep()) });
    expect(activated.status).toBe(200);
    expect(activated.body.data.recoveryCodes).toHaveLength(RECOVERY_CODE_COUNT);

    const after = await client.get(twoFa());
    expect(after.body.data).toMatchObject({
      enabled: true,
      pendingEnrollment: false,
      recoveryCodesRemaining: RECOVERY_CODE_COUNT,
    });
    expect(after.body.data.enabledAt).not.toBeNull();

    // The secret is never readable again, and the stored one is encrypted.
    const row = await prisma.user.findUniqueOrThrow({ where: { id: client.user.id } });
    expect(row.totpSecretEnc).not.toBeNull();
    expect(row.totpPendingSecretEnc).toBeNull();
    expect(Buffer.from(row.totpSecretEnc as Uint8Array).includes(secret)).toBe(false);
    // Recovery codes are stored hashed.
    const stored = await prisma.totpRecoveryCode.findMany({ where: { userId: client.user.id } });
    expect(stored).toHaveLength(RECOVERY_CODE_COUNT);
    const plain = activated.body.data.recoveryCodes as string[];
    expect(stored.map((s) => s.hash)).not.toContain(plain[0]);
    expect(stored.map((s) => s.hash)).toContain(hashRecoveryCode(plain[0] as string));

    expectError(await client.post(twoFa('/enroll')), 'LSE-CONF-001', 409);
    const audit = await prisma.auditLog.findMany({ where: { action: 'auth.2fa_enrolled' } });
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit)).not.toContain(plain[0] as string);

    // `/users/me` reflects the new state and the enrolling session is already verified.
    const me = await client.get(`${API_PREFIX}/users/me`);
    expect(me.body.data).toMatchObject({ twoFactorEnabled: true, mfaRequired: false });
  });

  it('activation needs a started enrollment', async () => {
    const client = await login(app);
    expectError(await client.post(twoFa('/activate'), { code: '123456' }), 'LSE-VAL-001', 400);
  });
});

describe('challenge (POST /auth/2fa/verify)', () => {
  it('blocks a fresh session until it is verified, then rotates the session token', async () => {
    const email = 'mfa-user@example.com';
    const first = await login(app, email);
    const { secret } = await enroll(first);

    // A brand-new session of the same user must pass the challenge first.
    const second = await login(app, email);
    const me = await second.get(`${API_PREFIX}/users/me`);
    expect(me.body.data).toMatchObject({ twoFactorEnabled: true, mfaRequired: true });
    expectError(await second.get(`${API_PREFIX}/orgs`), 'LSE-AUTH-012', 403);
    // 2FA endpoints and /users/me stay reachable so the UI can recover.
    expect((await second.get(twoFa())).status).toBe(200);

    const sessionsBefore = await prisma.authSession.findMany({ where: { userId: first.user.id } });
    const unverifiedId = sessionsBefore.find((s) => s.mfaVerifiedAt === null)?.id;
    expect(unverifiedId).toBeDefined();
    const verified = await second.post(`${API_PREFIX}/auth/2fa/verify`, {
      code: nextCode(secret),
    });
    expect(verified.status, JSON.stringify(verified.body)).toBe(200);
    expect(verified.body.data).toMatchObject({ verified: true, recoveryCodesRemaining: null });
    expect(String(verified.headers['set-cookie'])).toContain('loose_session=');

    // Session fixation protection: the pre-challenge session id no longer exists.
    const sessionsAfter = await prisma.authSession.findMany({ where: { userId: first.user.id } });
    expect(sessionsAfter).toHaveLength(sessionsBefore.length);
    expect(sessionsAfter.map((s) => s.id)).not.toContain(unverifiedId);
    expect(sessionsAfter.every((s) => s.mfaVerifiedAt !== null)).toBe(true);

    expect((await second.get(`${API_PREFIX}/orgs`)).status).toBe(200);
    const audit = await prisma.auditLog.findFirst({ where: { action: 'auth.2fa_verified' } });
    expect(audit?.actorId).toBe(first.user.id);
  });

  it('refuses a replayed code and locks out after repeated failures', async () => {
    const email = 'mfa-lockout@example.com';
    const first = await login(app, email);
    const { secret } = await enroll(first);
    const used = totpCode(secret, totpStep());

    // The code that activated enrollment cannot be replayed on a new session.
    const second = await login(app, email);
    expectError(
      await second.post(`${API_PREFIX}/auth/2fa/verify`, { code: used }),
      'LSE-AUTH-010',
      401,
    );
    const replayAudit = await prisma.auditLog.findFirst({
      where: { action: 'auth.2fa_failed' },
      orderBy: { createdAt: 'desc' },
    });
    expect(replayAudit?.meta).toMatchObject({ replayed: true });

    // Four more failures exhaust the budget (the replay above was the first).
    for (let i = 1; i < TWO_FACTOR_MAX_FAILURES; i++) {
      expectError(
        await second.post(`${API_PREFIX}/auth/2fa/verify`, { code: '000000' }),
        'LSE-AUTH-010',
        401,
      );
    }
    const locked = await second.post(`${API_PREFIX}/auth/2fa/verify`, { code: nextCode(secret) });
    expectError(locked, 'LSE-AUTH-008', 429);
    expect(Number(locked.headers['retry-after'])).toBeGreaterThan(0);
    // Still locked out even with a valid code.
    expectError(
      await second.post(`${API_PREFIX}/auth/2fa/verify`, { code: nextCode(secret) }),
      'LSE-AUTH-008',
      429,
    );
  });

  it('accepts a recovery code once and counts the remainder', async () => {
    const email = 'mfa-recovery@example.com';
    const first = await login(app, email);
    const { recoveryCodes } = await enroll(first);
    const code = recoveryCodes[0] as string;

    const second = await login(app, email);
    const used = await second.post(`${API_PREFIX}/auth/2fa/verify`, { recoveryCode: code });
    expect(used.status, JSON.stringify(used.body)).toBe(200);
    expect(used.body.data).toMatchObject({
      verified: true,
      recoveryCodesRemaining: RECOVERY_CODE_COUNT - 1,
    });
    expect((await second.get(`${API_PREFIX}/orgs`)).status).toBe(200);
    expect((await first.get(twoFa())).body.data.recoveryCodesRemaining).toBe(
      RECOVERY_CODE_COUNT - 1,
    );

    // A used code is dead, as is an unknown one.
    const third = await login(app, email);
    expectError(
      await third.post(`${API_PREFIX}/auth/2fa/verify`, { recoveryCode: code }),
      'LSE-AUTH-010',
      401,
    );
    expectError(
      await third.post(`${API_PREFIX}/auth/2fa/verify`, { recoveryCode: 'aaaaa-bbbbb' }),
      'LSE-AUTH-010',
      401,
    );
    const audit = await prisma.auditLog.findFirst({ where: { action: 'auth.2fa_recovery_used' } });
    expect(audit?.meta).toMatchObject({ remaining: RECOVERY_CODE_COUNT - 1 });
  });

  it('regenerates recovery codes and invalidates the old ones', async () => {
    const client = await login(app);
    const { secret, recoveryCodes } = await enroll(client);
    const regenerated = await client.post(twoFa('/recovery-codes'), { code: nextCode(secret) });
    expect(regenerated.status, JSON.stringify(regenerated.body)).toBe(200);
    const fresh = regenerated.body.data.recoveryCodes as string[];
    expect(fresh).toHaveLength(RECOVERY_CODE_COUNT);
    expect(fresh).not.toContain(recoveryCodes[0]);
    const stored = await prisma.totpRecoveryCode.findMany({ where: { userId: client.user.id } });
    expect(stored).toHaveLength(RECOVERY_CODE_COUNT);
    expect(stored.map((s) => s.hash)).not.toContain(hashRecoveryCode(recoveryCodes[0] as string));
    expect(
      await prisma.auditLog.count({ where: { action: 'auth.2fa_recovery_regenerated' } }),
    ).toBe(1);
  });

  it('verify requires a session and rejects a code when 2FA is off', async () => {
    const client = await login(app);
    expectError(
      await client.post(`${API_PREFIX}/auth/2fa/verify`, { code: '123456' }),
      'LSE-VAL-001',
      400,
    );
    expectError(
      await client.post(`${API_PREFIX}/auth/2fa/verify`, { code: 'abc' }),
      'LSE-VAL-001',
      400,
    );
  });
});

describe('disable', () => {
  it('needs a valid code and clears the secret, codes and session state', async () => {
    const client = await login(app);
    const { secret } = await enroll(client);
    expectError(await client.post(twoFa('/disable'), { code: '000000' }), 'LSE-AUTH-010', 401);
    const disabled = await client.post(twoFa('/disable'), { code: nextCode(secret) });
    expect(disabled.status, JSON.stringify(disabled.body)).toBe(204);
    const row = await prisma.user.findUniqueOrThrow({ where: { id: client.user.id } });
    expect(row).toMatchObject({ totpSecretEnc: null, totpEnabledAt: null, totpLastStep: null });
    expect(await prisma.totpRecoveryCode.count({ where: { userId: client.user.id } })).toBe(0);
    expect(
      (await prisma.authSession.findMany({ where: { userId: client.user.id } })).every(
        (s) => s.mfaVerifiedAt === null,
      ),
    ).toBe(true);
    expect((await client.get(twoFa())).body.data.enabled).toBe(false);
    expect(await prisma.auditLog.count({ where: { action: 'auth.2fa_disabled' } })).toBe(1);
  });
});

describe('org requireAdmin2fa', () => {
  async function orgWithRequired2fa() {
    const owner = await login(app, 'owner-2fa@example.com');
    const org = await createOrg(owner, `Secured ${Math.random().toString(36).slice(2, 7)}`);
    const admin = await login(app, 'admin-2fa@example.com');
    await addMember(org.id, admin.user.id, 'ADMIN');
    const member = await login(app, 'member-2fa@example.com');
    await addMember(org.id, member.user.id, 'MEMBER');
    return { owner, admin, member, org };
  }

  it('reports un-enrolled admins and challenges them until they enroll', async () => {
    const w = await orgWithRequired2fa();
    const security = `${API_PREFIX}/orgs/${w.org.id}/identity/security`;
    const before = await w.owner.get(security);
    expect(before.status).toBe(200);
    expect(before.body.data).toMatchObject({ requireAdmin2fa: false, adminsWithout2fa: 2 });

    const on = await w.owner.put(security, { requireAdmin2fa: true });
    expect(on.status, JSON.stringify(on.body)).toBe(200);
    expect(on.body.data.requireAdmin2fa).toBe(true);

    // The owner (not enrolled) is now challenged on org routes.
    expectError(await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-AUTH-012', 403);
    expectError(await w.admin.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-AUTH-012', 403);
    // Members are unaffected.
    expect((await w.member.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
    // Non-org routes stay reachable so enrollment is possible.
    expect((await w.owner.get(twoFa())).body.data.requiredByOrg).toBe(true);

    await enroll(w.owner);
    expect((await w.owner.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);
    expect((await w.owner.get(security)).body.data.adminsWithout2fa).toBe(1);
  });

  it('an enrolled admin on an unverified session is challenged, and cannot disable 2FA', async () => {
    const w = await orgWithRequired2fa();
    const { secret } = await enroll(w.admin);
    await w.owner.put(`${API_PREFIX}/orgs/${w.org.id}/identity/security`, {
      requireAdmin2fa: true,
    });
    expect((await w.admin.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    // A new (unverified) session of the same admin is blocked everywhere.
    const fresh = await login(app, 'admin-2fa@example.com');
    expectError(await fresh.get(`${API_PREFIX}/orgs/${w.org.id}`), 'LSE-AUTH-012', 403);
    expect(
      (await fresh.post(`${API_PREFIX}/auth/2fa/verify`, { code: nextCode(secret) })).status,
    ).toBe(200);
    expect((await fresh.get(`${API_PREFIX}/orgs/${w.org.id}`)).status).toBe(200);

    // Disabling is refused while the org requires it (the org check runs before the code check).
    expectError(
      await w.admin.post(twoFa('/disable'), { code: nextCode(secret) }),
      'LSE-AUTH-012',
      403,
    );
    expect(
      (await prisma.user.findUniqueOrThrow({ where: { id: w.admin.user.id } })).totpEnabledAt,
    ).not.toBeNull();
  });

  it('an API token of an un-enrolled admin is refused as well', async () => {
    const w = await orgWithRequired2fa();
    const created = await w.owner.post(`${API_PREFIX}/users/me/tokens`, {
      orgId: w.org.id,
      name: 'ci',
      scopes: ['org:read'],
    });
    expect(created.status).toBe(201);
    const token = created.body.data.token as string;
    await w.owner.put(`${API_PREFIX}/orgs/${w.org.id}/identity/security`, {
      requireAdmin2fa: true,
    });
    const res = await request(app)
      .get(`${API_PREFIX}/orgs/${w.org.id}`)
      .set('authorization', `Bearer ${token}`);
    expectError(res, 'LSE-AUTH-012', 403);
  });

  it('admin_2fa=off disables the whole feature', async () => {
    const off = makeApp({ env: { FEATURE_FLAGS: 'admin_2fa=off' } });
    const owner = await login(off.app, 'flag-2fa@example.com');
    const org = await createOrg(owner, `Flagged ${Math.random().toString(36).slice(2, 7)}`);
    expectError(await owner.get(twoFa()), 'LSE-SYS-007', 503);
    await prisma.organization.update({
      where: { id: org.id },
      data: { requireAdmin2fa: true },
    });
    expect((await owner.get(`${API_PREFIX}/orgs/${org.id}`)).status).toBe(200);
  });
});
