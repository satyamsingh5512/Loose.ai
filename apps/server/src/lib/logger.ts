/**
 * Pino logger with secret redaction. Never log raw API keys, tokens, cookies or
 * env var values — the redact paths below are a safety net, not a licence.
 */
import pino, { type DestinationStream, type Logger } from 'pino';
import { scrubSecrets } from '@loose/shared';

export type { Logger };

export const REDACT_PATHS = [
  'authorization',
  'cookie',
  'set-cookie',
  'clientSecret',
  'secretEnc',
  'totpSecret',
  'recoveryCodes',
  'webhookUrl',
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  'headers.authorization',
  'headers.cookie',
  'apiKey',
  'key',
  'token',
  'envVars',
  '*.apiKey',
  '*.key',
  '*.token',
  '*.accessToken',
  '*.refreshToken',
  '*.access_token',
  '*.refresh_token',
  '*.secret',
  '*.password',
  '*.envVars',
  '*.*.apiKey',
  '*.*.key',
  '*.*.token',
  '*.*.envVars',
  'body',
  'req.body',
];

export interface LoggerOptions {
  level: string;
  pretty?: boolean;
  /** Custom destination (tests capture output through this). */
  destination?: DestinationStream;
}

export function createLogger(opts: LoggerOptions): Logger {
  const options: pino.LoggerOptions = {
    level: opts.level,
    base: { service: 'loose-server' },
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    serializers: {
      err: (err: unknown) => {
        const s = pino.stdSerializers.err(err as Error);
        if (s && typeof s.message === 'string') s.message = scrubSecrets(s.message);
        if (s && typeof s.stack === 'string') s.stack = scrubSecrets(s.stack);
        return s;
      },
    },
  };
  if (opts.destination) return pino(options, opts.destination);
  if (opts.pretty) {
    return pino({ ...options, transport: { target: 'pino-pretty', options: { colorize: true } } });
  }
  return pino(options);
}

/**
 * Strip query strings and mask path-embedded tokens before a URL is logged
 * (OAuth callbacks carry `code`/`state`; invite links carry the invite token).
 */
export function safeUrlForLog(url: string | undefined): string {
  if (!url) return '';
  const path = url.split('?')[0] ?? '';
  return scrubSecrets(path.replace(/(\/orgs\/invites\/)[^/]+/, '$1[REDACTED]'));
}
