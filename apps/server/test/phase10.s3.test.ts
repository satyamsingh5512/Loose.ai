/**
 * Phase 10 (W2): S3 / MinIO object storage behind the `ObjectStorage` interface — real AWS SDK
 * client, requests answered by an in-memory S3 over MSW. Covers prefixing, signed URLs, outage →
 * LSE-SYS-008, config wiring and a full data-export round trip through S3.
 */
import { unzipSync } from 'fflate';
import { http, HttpResponse } from 'msw';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { DATA_EXPORT_CONTENT_TYPE, ERROR_CODES } from '@loose/shared';
import { AppError } from '../src/lib/errors';
import {
  LocalObjectStorage,
  S3ObjectStorage,
  attachmentDisposition,
  s3ConfigFromEnv,
  type ObjectStorage,
  type S3StorageConfig,
} from '../src/lib/storage';
import {
  createMswServer,
  expectError,
  login,
  makeApp,
  onUnhandled,
  resetDb,
  testPrisma,
} from './helpers';
import { createFakeS3, FAKE_S3_BUCKET, FAKE_S3_ENDPOINT } from './phase10.s3.fake';

const server = createMswServer();
const fake = createFakeS3();
const prisma = testPrisma();

const config = (over: Partial<S3StorageConfig> = {}): S3StorageConfig => ({
  bucket: FAKE_S3_BUCKET,
  region: 'us-east-1',
  endpoint: FAKE_S3_ENDPOINT,
  accessKeyId: 'AKIAFAKEFAKEFAKE',
  secretAccessKey: 'fake-secret-access-key',
  forcePathStyle: true,
  prefix: 'tenant-a/',
  signedUrlTtlSec: 300,
  ...over,
});

const text = async (s: NodeJS.ReadableStream) => {
  const chunks: Buffer[] = [];
  for await (const c of s) chunks.push(Buffer.from(c as Uint8Array));
  return Buffer.concat(chunks).toString('utf8');
};

async function expectStorageDown(p: Promise<unknown>) {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AppError);
  expect((err as AppError).code).toBe('LSE-SYS-008');
  expect((err as AppError).status).toBe(503);
  expect((err as AppError).retryable).toBe(true);
}

beforeAll(() => {
  server.listen({ onUnhandledRequest: onUnhandled });
});
beforeEach(() => {
  server.use(...fake.handlers);
});
afterEach(() => {
  server.resetHandlers();
  fake.reset();
});
afterAll(async () => {
  server.close();
  await prisma.$disconnect();
});

describe('S3ObjectStorage', () => {
  it('puts, gets and deletes objects under the configured prefix with signed requests', async () => {
    const s3 = new S3ObjectStorage(config());
    const put = await s3.put('sessions/s1/shot.png', 'hello-s3', { contentType: 'image/png' });
    expect(put).toEqual({ bytes: 8 });
    expect([...fake.objects.keys()]).toEqual(['tenant-a/sessions/s1/shot.png']);
    expect(fake.objects.get('tenant-a/sessions/s1/shot.png')?.contentType).toBe('image/png');
    const putReq = fake.requests.find((r) => r.method === 'PUT');
    expect(putReq?.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAFAKEFAKEFAKE\//);
    expect(putReq?.authorization).not.toContain('fake-secret-access-key');

    const got = await s3.get('sessions/s1/shot.png');
    expect(got?.bytes).toBe(8);
    expect(await text(got!.stream)).toBe('hello-s3');

    await s3.delete('sessions/s1/shot.png');
    expect(fake.objects.size).toBe(0);
    expect(await s3.get('sessions/s1/shot.png')).toBeNull();
  });

  it('stores binary data byte-for-byte and accepts Uint8Array', async () => {
    const s3 = new S3ObjectStorage(config({ prefix: '' }));
    const data = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(await s3.put('bin/all-bytes.bin', data)).toEqual({ bytes: 256 });
    const got = await s3.get('bin/all-bytes.bin');
    const chunks: Buffer[] = [];
    for await (const c of got!.stream) chunks.push(Buffer.from(c as Uint8Array));
    expect([...Buffer.concat(chunks)]).toEqual([...data]);
  });

  it('treats a missing key as null and deleting a missing key as success', async () => {
    const s3 = new S3ObjectStorage(config());
    expect(await s3.get('nope/missing.png')).toBeNull();
    await expect(s3.delete('nope/missing.png')).resolves.toBeUndefined();
  });

  it('rejects unsafe keys before any request (same rules as local storage)', async () => {
    const s3 = new S3ObjectStorage(config());
    for (const key of ['../escape', 'a/../b', '/abs', 'a//b', 'spa ce']) {
      await expect(s3.put(key, 'x')).rejects.toMatchObject({ code: 'LSE-SYS-001' });
      await expect(s3.get(key)).rejects.toMatchObject({ code: 'LSE-SYS-001' });
    }
    expect(fake.requests).toHaveLength(0);
  });

  it('maps outages and permission errors to LSE-SYS-008 (retryable, 503)', async () => {
    const s3 = new S3ObjectStorage(config());
    fake.failWith = 500;
    await expectStorageDown(s3.put('a/b.txt', 'x'));
    fake.failWith = 403;
    await expectStorageDown(s3.get('a/b.txt'));
    fake.failWith = 500;
    await expectStorageDown(s3.delete('a/b.txt'));
    fake.failWith = 503;
    await expectStorageDown(s3.ping());
    expect(ERROR_CODES['LSE-SYS-008'].status).toBe(503);
  });

  it('maps connection failures to LSE-SYS-008 too', async () => {
    const dead = new S3ObjectStorage(config({ endpoint: 'http://unreachable.s3.test:9000' }));
    server.use(http.all('http://unreachable.s3.test:9000/*', () => HttpResponse.error()));
    await expectStorageDown(dead.put('a/b.txt', 'x'));
  });

  it('ping() succeeds against a healthy bucket', async () => {
    await expect(new S3ObjectStorage(config()).ping()).resolves.toBeUndefined();
  });

  describe('signed URLs', () => {
    it('are presigned locally (no network), prefixed, short-lived and path-style', async () => {
      const s3 = new S3ObjectStorage(config());
      const before = fake.requests.length;
      const raw = await s3.signedUrl('exports/e1.zip', { filename: 'export.zip' });
      expect(fake.requests.length).toBe(before);
      const url = new URL(raw!);
      expect(url.origin).toBe(FAKE_S3_ENDPOINT);
      expect(url.pathname).toBe(`/${FAKE_S3_BUCKET}/tenant-a/exports/e1.zip`);
      expect(url.searchParams.get('X-Amz-Algorithm')).toBe('AWS4-HMAC-SHA256');
      expect(url.searchParams.get('X-Amz-Expires')).toBe('300');
      expect(url.searchParams.get('X-Amz-Signature')).toMatch(/^[0-9a-f]{64}$/);
      expect(url.searchParams.get('response-content-disposition')).toBe(
        'attachment; filename="export.zip"',
      );
      expect(raw).not.toContain('fake-secret-access-key');
    });

    it('clamp the lifetime to 30 s – 1 h and use the configured default', async () => {
      const s3 = new S3ObjectStorage(config({ signedUrlTtlSec: 120 }));
      const expires = async (ttlSec?: number) =>
        new URL(
          (await s3.signedUrl('a/b.txt', ttlSec === undefined ? {} : { ttlSec }))!,
        ).searchParams.get('X-Amz-Expires');
      expect(await expires()).toBe('120');
      expect(await expires(1)).toBe('1'); // explicit short TTLs are honoured (P10-SEC-016)
      expect(await expires(999_999)).toBe('3600');
      expect(await expires(600)).toBe('600');
    });

    it('can be fetched and the file name cannot inject headers', async () => {
      const s3 = new S3ObjectStorage(config());
      await s3.put('exports/e2.zip', 'zip-bytes', { contentType: DATA_EXPORT_CONTENT_TYPE });
      const url = await s3.signedUrl('exports/e2.zip', {
        filename: 'evil"\r\nSet-Cookie: x=1.zip',
        contentType: 'application/zip',
      });
      expect(attachmentDisposition('evil"\r\nSet-Cookie: x=1.zip')).not.toMatch(/[\r\n]/);
      const res = await fetch(url!);
      expect(res.status).toBe(200);
      expect(await res.text()).toBe('zip-bytes');
      expect(res.headers.get('content-disposition')).toMatch(
        /^attachment; filename="[A-Za-z0-9._-]+"$/,
      );
    });

    it('local storage has no signed URLs (callers stream through the API)', async () => {
      expect(
        (new LocalObjectStorage('/tmp/loose-unused') as ObjectStorage).signedUrl,
      ).toBeUndefined();
    });
  });
});

describe('configuration', () => {
  it('derives the S3 settings (normalised prefix) from env', () => {
    const { env } = makeApp({
      env: {
        ARTIFACT_STORAGE: 's3',
        S3_BUCKET: 'bkt',
        S3_REGION: 'eu-west-1',
        S3_ENDPOINT: FAKE_S3_ENDPOINT,
        S3_ACCESS_KEY_ID: 'AK',
        S3_SECRET_ACCESS_KEY: 'SK',
        S3_FORCE_PATH_STYLE: 'true',
        S3_PREFIX: 'loose/prod',
        S3_SIGNED_URL_TTL_SEC: '90',
      },
    });
    expect(s3ConfigFromEnv(env)).toEqual({
      bucket: 'bkt',
      region: 'eu-west-1',
      endpoint: FAKE_S3_ENDPOINT,
      accessKeyId: 'AK',
      secretAccessKey: 'SK',
      forcePathStyle: true,
      prefix: 'loose/prod/',
      signedUrlTtlSec: 90,
    });
  });

  it('selects the S3 backend for ARTIFACT_STORAGE=s3 and the local one otherwise', () => {
    const s3 = makeApp({ env: { ARTIFACT_STORAGE: 's3', S3_BUCKET: 'bkt' } });
    expect(s3.ctx.storage).toBeInstanceOf(S3ObjectStorage);
    expect(makeApp().ctx.storage).toBeInstanceOf(LocalObjectStorage);
  });
});

describe('data export through S3', () => {
  const s3Env = {
    ARTIFACT_STORAGE: 's3',
    S3_BUCKET: FAKE_S3_BUCKET,
    S3_ENDPOINT: FAKE_S3_ENDPOINT,
    S3_ACCESS_KEY_ID: 'AKIAFAKEFAKEFAKE',
    S3_SECRET_ACCESS_KEY: 'fake-secret-access-key',
    S3_FORCE_PATH_STYLE: 'true',
    S3_PREFIX: 'prod',
  };

  beforeEach(async () => {
    await resetDb(prisma);
  });

  it('stores the ZIP in S3 and redirects the download to a short-lived signed URL', async () => {
    const { app, ctx } = makeApp({ env: s3Env });
    const me = await login(app, 'export-s3@example.com', 'Exporter');
    const created = await me.post('/api/v1/users/me/privacy/exports');
    expect(created.status).toBe(202);
    await ctx.jobs.onIdle();

    const listed = await me.get('/api/v1/users/me/privacy/exports');
    const dto = listed.body.data[0];
    expect(dto).toMatchObject({ status: 'SUCCEEDED', kind: 'USER' });
    const key = `prod/exports/${dto.id}.zip`;
    expect(fake.objects.get(key)?.contentType).toBe(DATA_EXPORT_CONTENT_TYPE);
    // the storage key is internal: never in API output
    expect(JSON.stringify(listed.body)).not.toContain('.zip');
    expect(JSON.stringify(listed.body)).not.toContain('prod/');

    const dl = await me.get(dto.downloadUrl as string).redirects(0);
    expect(dl.status).toBe(302);
    expect(dl.headers['cache-control']).toBe('no-store');
    const location = new URL(dl.headers.location as string);
    expect(location.origin).toBe(FAKE_S3_ENDPOINT);
    expect(location.pathname).toBe(`/${FAKE_S3_BUCKET}/${key}`);
    expect(location.searchParams.get('X-Amz-Expires')).toBe('300');

    const file = await fetch(location);
    const files = unzipSync(new Uint8Array(await file.arrayBuffer()));
    expect(Object.keys(files)).toContain('manifest.json');
    expect(JSON.parse(Buffer.from(files['profile.json']!).toString()).email).toBe(
      'export-s3@example.com',
    );
    const audit = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'data_export.download' },
    });
    expect(audit.meta).toMatchObject({ via: 'redirect' });
  });

  it('marks the export FAILED with LSE-SYS-008 when S3 is down, and succeeds on a retry', async () => {
    const { app, ctx } = makeApp({ env: s3Env });
    const me = await login(app);
    fake.failWith = 500;
    expect((await me.post('/api/v1/users/me/privacy/exports')).status).toBe(202);
    await ctx.jobs.onIdle();
    const failed = (await me.get('/api/v1/users/me/privacy/exports')).body.data[0];
    expect(failed).toMatchObject({ status: 'FAILED', error: 'LSE-SYS-008', downloadUrl: null });
    expect(fake.objects.size).toBe(0);

    fake.failWith = null;
    expect((await me.post('/api/v1/users/me/privacy/exports')).status).toBe(202); // not "active" any more
    await ctx.jobs.onIdle();
    const ok = (await me.get('/api/v1/users/me/privacy/exports')).body.data[0];
    expect(ok.status).toBe('SUCCEEDED');
  });

  it('returns the LSE-SYS-008 envelope when streaming from a broken backend', async () => {
    const storage = new S3ObjectStorage(config({ prefix: 'prod/' }));
    // no direct links → the API has to stream, and the backend fails
    (storage as { signedUrl?: unknown }).signedUrl = undefined;
    const { app, ctx } = makeApp({ context: { storage } });
    const me = await login(app);
    await me.post('/api/v1/users/me/privacy/exports');
    await ctx.jobs.onIdle();
    const dto = (await me.get('/api/v1/users/me/privacy/exports')).body.data[0];
    expect(dto.status).toBe('SUCCEEDED');

    fake.failWith = 500;
    const res = await me.get(dto.downloadUrl as string);
    expectError(res, 'LSE-SYS-008', 503);
    expect(res.body.error.retryable).toBe(true);

    fake.failWith = null;
    const stream = await me
      .get(dto.downloadUrl as string)
      .buffer(true)
      .parse((res2, cb) => {
        const chunks: Buffer[] = [];
        res2.on('data', (c: Buffer) => chunks.push(c));
        res2.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(stream.status).toBe(200);
    expect(stream.headers['content-type']).toBe('application/zip');
    expect(Object.keys(unzipSync(new Uint8Array(stream.body as Buffer)))).toContain('profile.json');
  });
});
