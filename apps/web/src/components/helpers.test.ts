import type { MemberDto, Role } from '@loose/shared';
import { describe, expect, it } from 'vitest';
import { memberPermissions } from '@/components/org/MemberList';
import {
  envPatchFromRows,
  parseDotEnv,
  rowsFromEntries,
  validateEnvRows,
  type EnvRow,
} from '@/components/project/EnvEditor';
import { portMapFromRows, newPortRow } from '@/components/project/PortMapEditor';
import { visibleNavItems } from '@/components/layout/Sidebar';

const member = (role: Role): MemberDto => ({
  userId: `u_${role}`,
  orgId: 'org_1',
  role,
  lockedMode: null,
  user: { id: `u_${role}`, email: `${role}@x.com`, name: null, avatarUrl: null },
  createdAt: '2026-10-01T10:00:00.000Z',
});

describe('memberPermissions', () => {
  it('members and viewers cannot manage anyone', () => {
    expect(memberPermissions('MEMBER', member('VIEWER'), 1).canEdit).toBe(false);
    expect(memberPermissions('VIEWER', member('MEMBER'), 1).canRemove).toBe(false);
  });
  it('admins manage non-owners but cannot grant OWNER or touch owners', () => {
    const p = memberPermissions('ADMIN', member('MEMBER'), 1);
    expect(p.canEdit).toBe(true);
    expect(p.assignable).not.toContain('OWNER');
    const o = memberPermissions('ADMIN', member('OWNER'), 2);
    expect(o.canEdit).toBe(false);
    expect(o.reason).toMatch(/only an owner/i);
  });
  it('owners can grant OWNER, but the last owner is protected', () => {
    expect(memberPermissions('OWNER', member('ADMIN'), 1).assignable).toContain('OWNER');
    const last = memberPermissions('OWNER', member('OWNER'), 1);
    expect(last.canEdit).toBe(false);
    expect(last.canRemove).toBe(false);
    expect(last.reason).toMatch(/at least one owner/i);
    expect(memberPermissions('OWNER', member('OWNER'), 2).canRemove).toBe(true);
  });
});

describe('visibleNavItems', () => {
  it('filters admin pages by role', () => {
    const labels = (r: Role) => visibleNavItems('org_1', r).map((i) => i.label);
    expect(labels('VIEWER')).toEqual(['Dashboard', 'Sessions', 'Extensions']);
    expect(labels('ADMIN')).toContain('Organization settings');
  });
});

describe('env editor helpers', () => {
  const original = [
    { name: 'DATABASE_URL', secret: true },
    { name: 'PUBLIC_URL', secret: false },
  ];

  it('builds a merge patch: replace, delete, add — values never read back', () => {
    const rows: EnvRow[] = rowsFromEntries(original);
    rows[0] = { ...rows[0]!, value: 'postgres://new' };
    rows[1] = { ...rows[1]!, deleted: true };
    rows.push({
      key: 'n',
      name: 'STRIPE_KEY',
      value: 'sk',
      existing: false,
      secret: true,
      deleted: false,
    });
    expect(envPatchFromRows(rows, original)).toEqual({
      envVars: { DATABASE_URL: 'postgres://new', PUBLIC_URL: null, STRIPE_KEY: 'sk' },
      secretEnvVars: ['DATABASE_URL', 'STRIPE_KEY'],
    });
  });

  it('sends nothing when nothing changed', () => {
    expect(envPatchFromRows(rowsFromEntries(original), original)).toEqual({});
  });

  it('sends only secret flags when only flags changed', () => {
    const rows = rowsFromEntries(original).map((r) => ({ ...r, secret: true }));
    expect(envPatchFromRows(rows, original)).toEqual({
      secretEnvVars: ['DATABASE_URL', 'PUBLIC_URL'],
    });
  });

  it('validates names and duplicates', () => {
    const bad: EnvRow[] = [
      { key: 'a', name: '1BAD', value: 'x', existing: false, secret: false, deleted: false },
    ];
    expect(validateEnvRows(bad)).toMatch(/1BAD/);
    const dup: EnvRow[] = [
      { key: 'a', name: 'A', value: 'x', existing: false, secret: false, deleted: false },
      { key: 'b', name: 'A', value: 'y', existing: false, secret: false, deleted: false },
    ];
    expect(validateEnvRows(dup)).toMatch(/twice/);
  });

  it('parses .env files', () => {
    expect(parseDotEnv('# c\nexport A=1\nB="two words"\nC=\'3\'\ninvalid line\n')).toEqual([
      { name: 'A', value: '1' },
      { name: 'B', value: 'two words' },
      { name: 'C', value: '3' },
    ]);
  });
});

describe('portMapFromRows', () => {
  it('coerces ports and drops empty rows', () => {
    expect(
      portMapFromRows([newPortRow({ name: 'web', port: '3000', public: true }), newPortRow()]),
    ).toEqual([{ name: 'web', port: 3000, public: true }]);
  });
});
