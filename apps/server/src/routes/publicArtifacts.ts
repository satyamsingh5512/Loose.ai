/**
 * `GET /api/v1/public-artifacts/:token` — unauthenticated, signed, expiring links to
 * screenshot artifacts for PR bodies (see lib/publicArtifacts.ts). Only screenshots are
 * served; invalid/expired tokens and other kinds are reported as not found.
 */
import { Router } from 'express';
import type { AppContext } from '../context';
import { AppError } from '../lib/errors';
import { verifyArtifactToken } from '../lib/publicArtifacts';

export function publicArtifactsRouter(ctx: AppContext): Router {
  const r = Router();
  r.get('/:token', async (req, res) => {
    const token = String(req.params.token ?? '');
    const id = token.length <= 256 ? verifyArtifactToken(ctx.env.SESSION_SECRET, token) : null;
    const row = id ? await ctx.prisma.artifact.findUnique({ where: { id } }) : null;
    const obj =
      row && row.kind === 'screenshot' && row.storageKey
        ? await ctx.storage.get(row.storageKey)
        : null;
    if (!row || !obj)
      throw new AppError('LSE-NF-001', { devMessage: 'Artifact link is invalid or expired' });
    res.setHeader('Content-Type', row.contentType === 'image/jpeg' ? 'image/jpeg' : 'image/png');
    res.setHeader('Content-Length', String(obj.bytes));
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    // GitHub's image proxy fetches these cross-site.
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    obj.stream.on('error', () => res.destroy());
    obj.stream.pipe(res);
  });
  return r;
}
