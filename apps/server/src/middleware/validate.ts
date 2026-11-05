/**
 * Request validation with Zod. `body` and `params` are replaced with parsed
 * output; parsed `query` goes to `req.validatedQuery` (read-only in Express 5).
 * Failures throw ZodError → LSE-VAL-001 via the error handler.
 */
import type { Request, RequestHandler } from 'express';
import type { z } from 'zod';
import { AppError } from '../lib/errors';

export interface ValidateSchemas {
  body?: z.ZodType;
  query?: z.ZodType;
  params?: z.ZodType;
}

export function validate(schemas: ValidateSchemas): RequestHandler {
  return (req, _res, next) => {
    if (schemas.params) req.params = schemas.params.parse(req.params) as Request['params'];
    if (schemas.query) req.validatedQuery = schemas.query.parse(req.query);
    if (schemas.body) req.body = schemas.body.parse(req.body);
    next();
  };
}

/** Typed accessor for the parsed query. */
export function queryOf<T>(req: Request): T {
  return req.validatedQuery as T;
}

/**
 * Routes that take a raw (non-JSON) body: session attachment uploads (spec §8.12).
 * Paths are relative to the `/api/v1` mount point.
 */
const RAW_BODY_ROUTES: readonly RegExp[] = Object.freeze([
  /^\/sessions\/[A-Za-z0-9_-]+\/attachments\/?$/,
]);

export function isRawBodyRoute(method: string, path: string): boolean {
  return method === 'POST' && RAW_BODY_ROUTES.some((r) => r.test(path));
}

/**
 * State-changing requests that carry a body must be JSON → else LSE-VAL-003.
 * Raw-upload routes are exempt (their own parser validates the content type).
 */
export const requireJsonBody: RequestHandler = (req, _res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  if (isRawBodyRoute(req.method, req.path)) return next();
  const length = Number(req.headers['content-length'] ?? 0);
  const hasBody = length > 0 || req.headers['transfer-encoding'] !== undefined;
  if (hasBody && !req.is('application/json')) {
    return next(
      new AppError('LSE-VAL-003', {
        devMessage: `Expected Content-Type application/json, got ${req.headers['content-type'] ?? 'none'}`,
      }),
    );
  }
  next();
};
