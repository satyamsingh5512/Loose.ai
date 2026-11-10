import { describe, expect, it } from 'vitest';
import { PassThrough } from 'node:stream';
import { createLogger, safeUrlForLog } from '../src/lib/logger';

describe('Phase 10 logging redaction', () => {
  it('redacts nested tokens, passwords and request credentials', () => {
    const out = new PassThrough();
    let text = '';
    out.on('data', (chunk) => {
      text += String(chunk);
    });
    const logger = createLogger({ level: 'info', destination: out });
    logger.info(
      {
        token: 'loose_pat_secret',
        nested: { refreshToken: 'refresh-secret', password: 'password-secret' },
        req: { headers: { authorization: 'Bearer secret', cookie: 'x=y' } },
      },
      'event',
    );
    logger.flush();
    expect(text).not.toContain('secret');
    expect(text).toContain('[REDACTED]');
  });
  it('never logs OAuth query data', () =>
    expect(safeUrlForLog('/auth/callback?code=secret&state=secret')).toBe('/auth/callback'));
});
