/**
 * Security headers (spec §15 "Headers") — moved here unchanged from app.ts by the Phase 10
 * FOUNDATION; OWNED BY W4 (review + tests in test/phase10.headers.test.ts).
 */
import type { RequestHandler } from 'express';
import helmet from 'helmet';
import type { Env } from '../config/env';

export function securityHeaders(env: Pick<Env, 'NODE_ENV'>): RequestHandler[] {
  const production = env.NODE_ENV === 'production';
  return [
    helmet({
      // JSON API: nothing should ever be rendered, framed or fetched from here.
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
        },
      },
      crossOriginResourcePolicy: { policy: 'same-site' },
      referrerPolicy: { policy: 'no-referrer' },
      strictTransportSecurity: production ? { maxAge: 31_536_000, includeSubDomains: true } : false,
    }),
    (_req, res, next) => {
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
      res.setHeader('Cache-Control', 'no-store');
      next();
    },
  ];
}
