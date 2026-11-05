import { randomBytes } from 'node:crypto';
import { nanoid } from 'nanoid';
import type { RequestHandler } from 'express';
import { REQUEST_ID_HEADER, REQUEST_ID_PREFIX } from '@loose/shared';

const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;
const nonZero = (s: string) => /[1-9a-f]/i.test(s);
function fresh(bytes: number) {
  return randomBytes(bytes).toString('hex');
}

/** Correlates a trusted W3C trace context with Loose's public request id. */
export const requestId: RequestHandler = (req, res, next) => {
  req.requestId = `${REQUEST_ID_PREFIX}${nanoid(21)}`;
  const incoming = typeof req.headers.traceparent === 'string' ? req.headers.traceparent : '';
  const parsed = TRACEPARENT.exec(incoming);
  req.traceId =
    parsed && nonZero(parsed[1]!) && nonZero(parsed[2]!) ? parsed[1]!.toLowerCase() : fresh(16);
  req.spanId = fresh(8);
  res.setHeader(REQUEST_ID_HEADER, req.requestId);
  res.setHeader('traceparent', `00-${req.traceId}-${req.spanId}-01`);
  next();
};
