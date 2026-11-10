/**
 * P10-SEC-012 remainder: MCP HTTP/SSE connection tests are DNS-pinned (`safeFetch`), like hooks
 * and outbound webhooks. `assertPublicUrl` resolves the host once; an unpinned client would
 * resolve it again when connecting, so a rebinding host (public first, loopback/metadata second)
 * could reach an internal socket. These tests run the production transport: the connect-time
 * answer is validated, and the connection goes to exactly the address that was validated.
 */
import type * as DnsPromises from 'node:dns/promises';
import http from 'node:http';
import net from 'node:net';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { API_PREFIX } from '@loose/shared';
import type { AppContext } from '../src/context';
import type { ResolvedAddress } from '../src/lib/net/dns';
import { safeFetch } from '../src/lib/net/safeFetch';
import { createOrg, login, makeApp, resetDb, testPrisma } from './helpers';

// The `assertPublicUrl` lookup (first resolution) always sees a public address.
vi.mock('node:dns/promises', async (orig) => ({
  ...(await orig<typeof DnsPromises>()),
  lookup: vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]),
}));

const { testMcpServer } = await import('../src/services/extensions.service');

const prisma = testPrisma();
const { app, ctx } = makeApp();

/** An "internal" service on loopback that counts every TCP connection it receives. */
let internal: net.Server;
let internalPort = 0;
let internalConnections = 0;

beforeEach(async () => {
  await resetDb(prisma);
  internalConnections = 0;
  internal = net.createServer((sock) => {
    internalConnections += 1;
    sock.destroy();
  });
  await new Promise<void>((resolve) => internal.listen(0, '127.0.0.1', resolve));
  internalPort = (internal.address() as net.AddressInfo).port;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await new Promise<void>((resolve) => internal.close(() => resolve()));
});

afterAll(async () => {
  await ctx.jobs.onIdle();
  await prisma.$disconnect();
});

/**
 * A production-mode context whose connect-time DNS answer is `answer`. Its `fetch` stands in for
 * an unpinned client whose OS resolver has rebound the host to the internal service: if the MCP
 * test ever used it, the internal service would see a connection.
 */
function productionCtx(answer: ResolvedAddress[]) {
  const lookup = vi.fn(async () => answer);
  const unpinnedFetch = vi.fn(async () => {
    await new Promise<void>((resolve, reject) => {
      const s = net.connect(internalPort, '127.0.0.1', () => {
        s.destroy();
        resolve();
      });
      s.on('error', reject);
    });
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }), {
      headers: { 'content-type': 'application/json' },
    });
  });
  const prod = {
    ...ctx,
    env: { ...ctx.env, NODE_ENV: 'production' },
    dns: { lookup, resolveTxt: async () => [] },
    fetch: unpinnedFetch,
  } as unknown as AppContext;
  return { prod, lookup, unpinnedFetch };
}

describe('P10-SEC-012: MCP connection tests cannot be DNS-rebound to an internal address', () => {
  it.each(['HTTP', 'SSE'] as const)(
    'a %s server answering public then loopback is refused and no internal socket opens',
    async (transport) => {
      const admin = await login(app);
      const orgDto = await createOrg(admin);
      const created = await admin.post(`${API_PREFIX}/orgs/${orgDto.id}/mcp-servers`, {
        scope: 'ORG',
        name: `rebind-${transport.toLowerCase()}`,
        transport,
        url: `https://mcp.rebind.example:${internalPort}/rpc`,
      });
      expect(created.status, JSON.stringify(created.body)).toBe(201);
      const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgDto.id } });
      const membership = await prisma.orgMember.findUniqueOrThrow({
        where: { userId_orgId: { userId: admin.user.id, orgId: org.id } },
      });

      for (const address of ['127.0.0.1', '169.254.169.254', '::ffff:127.0.0.1']) {
        const { prod, lookup, unpinnedFetch } = productionCtx([
          { address, family: address.includes(':') ? 6 : 4 },
        ]);
        await expect(
          testMcpServer(prod, org, { userId: admin.user.id, membership }, created.body.data.id),
        ).rejects.toMatchObject({ code: 'LSE-MCP-004' });
        expect(lookup).toHaveBeenCalledTimes(1);
        expect(unpinnedFetch).not.toHaveBeenCalled();
      }
      expect(internalConnections).toBe(0);
    },
  );
});

describe('safeFetch connects to the address it validated (Node/Bun happy-eyeballs lookup)', () => {
  /**
   * Redirect the pinned connection to a local server while recording which address the pinned
   * lookup handed to the socket layer, in whichever shape (`all: true` or not) it was asked for.
   */
  function captureAndRedirect(localPort: number) {
    const original = http.request.bind(http);
    const pinnedTo: string[] = [];
    vi.spyOn(http, 'request').mockImplementation(((
      opts: http.RequestOptions,
      cb?: (res: http.IncomingMessage) => void,
    ) => {
      const pinnedLookup = opts.lookup as unknown as (
        host: string,
        o: { all?: boolean },
        done: (err: Error | null, a: unknown, f?: number) => void,
      ) => void;
      return original(
        {
          ...opts,
          port: localPort,
          lookup: ((host: string, o: { all?: boolean }, done: (...a: unknown[]) => void) =>
            pinnedLookup(host, o, (err, a) => {
              const list = Array.isArray(a) ? (a as { address: string }[]) : [{ address: a }];
              pinnedTo.push(...list.map((x) => String(x.address)));
              const local = '127.0.0.1';
              done(
                err,
                Array.isArray(a) ? [{ address: local, family: 4 }] : local,
                Array.isArray(a) ? undefined : 4,
              );
            })) as unknown as http.RequestOptions['lookup'],
        },
        cb,
      );
    }) as unknown as typeof http.request);
    return pinnedTo;
  }

  it('pins to the single validated answer and returns an endless SSE stream on headers', async () => {
    const sse = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(': keep-alive\n\n'); // never ends
    });
    await new Promise<void>((resolve) => sse.listen(0, '127.0.0.1', resolve));
    try {
      const port = (sse.address() as net.AddressInfo).port;
      const pinnedTo = captureAndRedirect(port);
      const { prod, lookup } = productionCtx([{ address: '93.184.216.34', family: 4 }]);
      const res = await safeFetch(prod, 'http://mcp.public.example/sse', {
        allowHttp: true,
        headersOnly: true,
        timeoutMs: 5_000,
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/event-stream');
      expect(lookup).toHaveBeenCalledTimes(1);
      expect(pinnedTo).toEqual(['93.184.216.34']);
    } finally {
      sse.closeAllConnections();
      await new Promise<void>((resolve) => sse.close(() => resolve()));
    }
  });
});
