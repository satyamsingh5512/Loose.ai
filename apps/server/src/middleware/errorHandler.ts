/**
 * Single error handler (spec §16.7): every failure leaves as a §16.2 envelope.
 * - AppError → its catalog code
 * - ZodError → LSE-VAL-001 with per-field messages
 * - body-parser errors → LSE-VAL-001/002/003
 * - Prisma P2002 → LSE-ORG-004 (org slug) / LSE-CONF-001, P2025 → LSE-NF-001,
 *   connection failures → LSE-SYS-002
 * - anything else → LSE-SYS-001
 * devMessage is scrubbed of secrets and omitted for 5xx in production.
 */
import { Prisma } from '@prisma/client';
import type { ErrorRequestHandler, RequestHandler, Response } from 'express';
import { ZodError } from 'zod';
import { REQUEST_ID_HEADER, scrubSecrets, zodIssuesToFieldErrors } from '@loose/shared';
import { AppError } from '../lib/errors';
import type { Logger } from '../lib/logger';
import { safeUrlForLog } from '../lib/logger';

interface BodyParserError {
  type?: string;
  status?: number;
  expose?: boolean;
}

function isBodyParserError(err: unknown): err is BodyParserError & Error {
  return (
    err instanceof Error &&
    typeof (err as BodyParserError).type === 'string' &&
    typeof (err as BodyParserError).status === 'number'
  );
}

export function toAppError(err: unknown): AppError {
  if (err instanceof AppError) return err;

  if (err instanceof ZodError) {
    return new AppError('LSE-VAL-001', {
      fields: zodIssuesToFieldErrors(err.issues),
      devMessage: 'Request validation failed',
      cause: err,
    });
  }

  if (isBodyParserError(err)) {
    switch (err.type) {
      case 'entity.too.large':
        return new AppError('LSE-VAL-002', {
          devMessage: 'Request body exceeds the size limit',
          cause: err,
        });
      case 'entity.parse.failed':
        return new AppError('LSE-VAL-001', {
          devMessage: 'Malformed JSON body',
          fields: { _root: ['Malformed JSON'] },
          cause: err,
        });
      case 'encoding.unsupported':
      case 'charset.unsupported':
        return new AppError('LSE-VAL-003', { devMessage: err.message, cause: err });
      default:
        if (err.status && err.status < 500) {
          return new AppError('LSE-VAL-001', { devMessage: err.message, cause: err });
        }
    }
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === 'P2002') {
      const target = JSON.stringify(err.meta?.target ?? '');
      const model = String(err.meta?.modelName ?? '');
      if (model === 'Organization' && target.includes('slug')) {
        return new AppError('LSE-ORG-004', {
          devMessage: 'Unique constraint on Organization.slug',
          cause: err,
        });
      }
      return new AppError('LSE-CONF-001', {
        devMessage: `Unique constraint failed (${model})`,
        cause: err,
      });
    }
    if (err.code === 'P2025') {
      return new AppError('LSE-NF-001', { devMessage: 'Record not found', cause: err });
    }
    if (err.code.startsWith('P1')) {
      return new AppError('LSE-SYS-002', { devMessage: `Database error ${err.code}`, cause: err });
    }
  }
  if (err instanceof Prisma.PrismaClientInitializationError) {
    return new AppError('LSE-SYS-002', { devMessage: 'Database unavailable', cause: err });
  }

  const message = err instanceof Error ? err.message : String(err);
  return new AppError('LSE-SYS-001', { devMessage: message, cause: err });
}

export function sendError(res: Response, appErr: AppError, requestId: string, production: boolean) {
  const includeDev = !(production && appErr.status >= 500);
  if (appErr.headers) for (const [k, v] of Object.entries(appErr.headers)) res.setHeader(k, v);
  res.setHeader(REQUEST_ID_HEADER, requestId);
  res.status(appErr.status).json(appErr.toEnvelope(requestId, includeDev));
}

export function errorHandler(logger: Logger, production: boolean): ErrorRequestHandler {
  return (err, req, res, next) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    const appErr = toAppError(err);
    const requestId = req.requestId ?? 'req_unknown';
    const logPayload = {
      requestId,
      code: appErr.code,
      status: appErr.status,
      method: req.method,
      url: safeUrlForLog(req.originalUrl),
      userId: req.auth?.user.id,
      orgId: req.org?.id,
      devMessage: appErr.devMessage ? scrubSecrets(appErr.devMessage) : undefined,
    };
    if (appErr.status >= 500) {
      const cause = appErr.code === 'LSE-SYS-001' ? err : (appErr.cause ?? undefined);
      logger.error({ ...logPayload, err: cause }, 'request failed');
    } else {
      logger.warn(logPayload, 'request rejected');
    }
    sendError(res, appErr, requestId, production);
  };
}

/** Catch-all for unknown routes → LSE-NF-001. */
export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(
    new AppError('LSE-NF-001', {
      devMessage: `No route for ${req.method} ${safeUrlForLog(req.originalUrl)}`,
    }),
  );
};
