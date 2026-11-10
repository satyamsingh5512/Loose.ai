/**
 * Route inventory (Phase 10 §7.1, W4) — introspects the live Express 5 router stack of an app
 * built by `createApp(ctx)` and returns every mounted `METHOD path` pair, with path params in
 * their original `:name` form.
 *
 * Why this exists: Express 5's router (the `router` package) does not retain the original path
 * *pattern* string on `.use()` layers once it has been compiled into a matcher closure (verified
 * against `router@2.2.0`, the version this repo pins via Express 5.2.1) — `layer.path` is only
 * populated, as a *matched* concrete path, after a request has actually been dispatched through
 * it. Leaf `Route` layers (the ones created by `.get()/.post()/...`) are the exception: Express
 * still stores the literal pattern at `layer.route.path`, unregexp'd, forever.
 *
 * So: router *mount* prefixes (`app.use(prefix, subRouter)`) are recovered by temporarily
 * monkey-patching the shared router prototype's `.use` for the duration of `inventoryRoutes()`,
 * recording `(subRouterFunction -> mountPath)`. Nothing is patched outside that call, and the
 * patch is removed in a `finally` block even if route construction throws. Leaf route paths come
 * straight from `layer.route.path`. The two are joined while walking `app.router.stack`.
 *
 * This only works because `createApp` builds its entire router tree synchronously during the
 * call captured here — exactly how every call site in this codebase uses it.
 */
import express, { type Express, type Router } from 'express';

const ExpressModule = { Router: express.Router };

export interface RouteEntry {
  method: string; // 'GET', 'POST', ...
  /** Joined path, e.g. '/api/v1/orgs/:orgId/identity/sso'. Trailing slashes stripped (not '/'). */
  path: string;
  /** `${method} ${path}` for map keys / failure messages. */
  key: string;
}

interface ExpressLayer {
  route?: {
    path: string | string[];
    methods: Record<string, boolean>;
  };
  handle?: ((...args: unknown[]) => unknown) & { stack?: ExpressLayer[] };
}

interface ExpressRouterLike {
  stack: ExpressLayer[];
}

function joinPaths(prefix: string, segment: string): string {
  const left = prefix.replace(/\/+$/, '');
  const rightRaw = segment.startsWith('/') ? segment : `/${segment}`;
  const right = rightRaw === '/' ? '' : rightRaw.replace(/\/+$/, '');
  const joined = `${left}${right}`;
  return joined === '' ? '/' : joined;
}

/**
 * Find the router/app prototype that actually owns `.use` (walking up from an instance, since
 * Express 5 does not put it on the router function's own prototype — see inspection notes above).
 */
function findUseOwner(instance: object): { use: (...args: unknown[]) => unknown } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let proto: any = Object.getPrototypeOf(instance);
  let depth = 0;
  while (proto && depth < 10) {
    if (Object.prototype.hasOwnProperty.call(proto, 'use') && typeof proto.use === 'function') {
      return proto as { use: (...args: unknown[]) => unknown };
    }
    proto = Object.getPrototypeOf(proto);
    depth += 1;
  }
  throw new Error('routeInventory: could not locate the Router.prototype.use to patch');
}

/**
 * Build a `createApp`-shaped app with mount-path recording enabled, then return every route it
 * registered. `build` must synchronously construct and return the Express app (as every
 * `createApp(ctx)` call site in this repo does) — the patch is removed before this function
 * returns, win or lose.
 */
export function inventoryRoutes(build: () => Express): RouteEntry[] {
  // The `.use` prototype is shared across every Router/Express instance, so patching it via a
  // throwaway router also affects the app `build()` is about to construct.
  const throwaway = ExpressModule.Router();
  const proto = findUseOwner(throwaway);
  const origUse = proto.use;
  const mounts = new WeakMap<object, string[]>();

  (proto as unknown as { use: (...args: unknown[]) => unknown }).use = function patchedUse(
    this: unknown,
    ...args: unknown[]
  ) {
    let path = '/';
    let handlers = args;
    if (typeof args[0] === 'string' || Array.isArray(args[0]) || args[0] instanceof RegExp) {
      path = args[0] as string;
      handlers = args.slice(1);
    }
    for (const h of handlers) {
      if (h && typeof h === 'function' && Array.isArray((h as { stack?: unknown }).stack)) {
        const list = mounts.get(h) ?? [];
        list.push(path);
        mounts.set(h, list);
      }
    }
    return origUse.apply(this, args);
  };

  let app: Express;
  try {
    app = build();
  } finally {
    (proto as unknown as { use: (...args: unknown[]) => unknown }).use = origUse;
  }

  const entries: RouteEntry[] = [];
  const seen = new Set<string>();
  const visitedRouters = new Set<ExpressLayer['handle']>();

  function walk(router: ExpressRouterLike, prefix: string): void {
    for (const layer of router.stack) {
      if (layer.route) {
        const path = Array.isArray(layer.route.path) ? layer.route.path[0] : layer.route.path;
        const methods = Object.keys(layer.route.methods).filter((m) => layer.route?.methods[m]);
        for (const m of methods) {
          const full = joinPaths(prefix, path ?? '/');
          const key = `${m.toUpperCase()} ${full}`;
          if (seen.has(key)) continue;
          seen.add(key);
          entries.push({ method: m.toUpperCase(), path: full, key });
        }
      } else if (layer.handle && Array.isArray(layer.handle.stack)) {
        if (visitedRouters.has(layer.handle)) continue; // avoid infinite loops on self-referencing mounts
        visitedRouters.add(layer.handle);
        const prefixes = mounts.get(layer.handle) ?? ['/'];
        for (const p of prefixes) {
          walk(layer.handle as unknown as ExpressRouterLike, joinPaths(prefix, p));
        }
        visitedRouters.delete(layer.handle);
      }
      // Bare middleware/handler layers that are neither a Route nor a sub-router stack
      // (e.g. app.get('/metrics', fn) registers via `.get`, which internally creates a Route —
      // already covered above. Raw `app.use(path, fn)` with a plain handler contributes no
      // enumerable route and is intentionally not listed.)
    }
  }

  // `app.router` is the Express 5 top-level router (replaces the Express 4 `_router`).
  const topRouter = (app as unknown as { router: ExpressRouterLike }).router;
  walk(topRouter, '');

  return entries.sort((a, b) => a.key.localeCompare(b.key));
}

/** Normalize a route's path the same way `authzExpectations.ts` keys are written. */
export function normalizeRouteKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

export type { Router };
