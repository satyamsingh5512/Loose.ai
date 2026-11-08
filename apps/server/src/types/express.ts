/** Express request augmentation (populated by middleware). */
import type { ApiToken, AuthSession, Organization, OrgMember, User } from '@prisma/client';

export interface AuthContext {
  user: User;
  via: 'session' | 'token';
  session?: AuthSession;
  apiToken?: ApiToken;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      requestId: string;
      /** W3C trace context (Phase 10, W3: set by middleware/requestId.ts). */
      traceId?: string;
      spanId?: string;
      auth?: AuthContext;
      org?: Organization;
      membership?: OrgMember;
      /** Parsed query from validate({ query }) — Express 5 makes req.query read-only. */
      validatedQuery?: unknown;
    }
  }
}

export {};
