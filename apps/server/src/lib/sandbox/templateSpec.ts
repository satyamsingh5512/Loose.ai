/**
 * Template spec generation (spec §13.1): base image + tools + required services +
 * runner bundle. Repository dependencies are NOT baked into the template: that
 * would require embedding a GitHub credential in the template definition stored
 * at the provider, so installs run per session (startup commands) instead.
 */
import { createHash } from 'node:crypto';
import type { Project } from '@prisma/client';
import type { SupportedService } from '@loose/shared';
import { TemplateBuildError, type TemplateSpec } from './types';

export const BASE_IMAGE = 'node:22-bookworm';
export const BASE_APT_PACKAGES = [
  'git',
  'curl',
  'ca-certificates',
  'ripgrep',
  'jq',
  'chromium',
  'fonts-liberation',
  'fonts-noto-color-emoji',
  'sudo',
];

/** Runner runtime dependencies installed next to the copied runner bundle (pinned). */
export const RUNNER_RUNTIME_DEPS = [
  '@anthropic-ai/claude-agent-sdk@0.3.286',
  '@anthropic-ai/sdk@0.131.0',
  '@modelcontextprotocol/sdk@1.31.0',
  'playwright-core@1.63.0',
];

interface ServiceDef {
  label: string;
  apt: string[];
  install: string[];
  /** Started at session start (non-root user with passwordless sudo). */
  start: string;
}

/** `null` = not supported yet (→ LSE-TPL-003). */
export const SERVICE_DEFS: Readonly<Record<SupportedService, ServiceDef | null>> = Object.freeze({
  postgresql: {
    label: 'PostgreSQL',
    apt: ['postgresql', 'postgresql-contrib'],
    install: [],
    start:
      'sudo -n service postgresql start && sudo -n -u postgres psql -qc "ALTER USER postgres PASSWORD \'postgres\'"',
  },
  redis: {
    label: 'Redis',
    apt: ['redis-server'],
    install: [],
    start: 'sudo -n service redis-server start',
  },
  mysql: {
    label: 'MySQL (MariaDB)',
    apt: ['mariadb-server'],
    install: [],
    start: 'sudo -n service mariadb start',
  },
  minio: {
    label: 'MinIO',
    apt: [],
    install: [
      'curl -fsSL https://dl.min.io/server/minio/release/linux-amd64/minio -o /usr/local/bin/minio',
      'chmod +x /usr/local/bin/minio',
    ],
    start:
      'mkdir -p "$HOME/.minio-data" && (nohup minio server "$HOME/.minio-data" --address :9000 > /tmp/minio.log 2>&1 &)',
  },
  // Not packaged for Debian bookworm; needs the vendor repo. Planned.
  mongodb: null,
});

export function unsupportedServices(services: readonly string[]): string[] {
  return services.filter((s) => !SERVICE_DEFS[s as SupportedService]);
}

export function serviceStartCommands(services: readonly string[]) {
  return services.flatMap((s) => {
    const def = SERVICE_DEFS[s as SupportedService];
    return def ? [{ service: s, label: def.label, cmd: def.start }] : [];
  });
}

export function templateName(projectId: string, version: number): string {
  return `loose-${projectId.toLowerCase().replace(/[^a-z0-9-]/g, '')}-v${version}`;
}

export interface BuildSpecOptions {
  version: number;
  runnerBundleDir?: string | undefined;
}

export function buildTemplateSpec(
  project: Pick<Project, 'id' | 'requiredServices'>,
  opts: BuildSpecOptions,
): TemplateSpec {
  const bad = unsupportedServices(project.requiredServices);
  if (bad.length) {
    throw new TemplateBuildError('unsupported', `Unsupported service(s): ${bad.join(', ')}`);
  }
  const defs = project.requiredServices.map((s) => SERVICE_DEFS[s as SupportedService]!);
  return {
    name: templateName(project.id, opts.version),
    baseImage: BASE_IMAGE,
    aptPackages: [...new Set([...BASE_APT_PACKAGES, ...defs.flatMap((d) => d.apt)])],
    runCommands: [
      ...defs.flatMap((d) => d.install),
      'echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/loose && chmod 0440 /etc/sudoers.d/loose',
      'mkdir -p /sandbox-agent/runner /home/user/workspace /home/user/.loose && chown -R user:user /home/user',
      `cd /sandbox-agent/runner && (test -f package.json || echo '{"name":"loose-runner-runtime","private":true,"type":"module"}' > package.json) && npm install --omit=dev --no-audit --no-fund ${RUNNER_RUNTIME_DEPS.join(' ')}`,
    ],
    envs: {
      CHROMIUM_PATH: '/usr/bin/chromium',
      LOOSE_RUNNER_ENTRY: '/sandbox-agent/runner/dist/cli.js',
    },
    ...(opts.runnerBundleDir ? { runnerBundleDir: opts.runnerBundleDir } : {}),
  };
}

/** Hash of the inputs that require a rebuild when changed (LSE-TPL-008 detection). */
export function templateInputsHash(project: Pick<Project, 'requiredServices'>): string {
  return createHash('sha256')
    .update(JSON.stringify({ services: [...project.requiredServices].sort(), base: BASE_IMAGE }))
    .digest('hex')
    .slice(0, 32);
}
