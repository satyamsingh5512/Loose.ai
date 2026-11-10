/** In-memory S3 / MinIO stand-in for MSW (path-style, `http://s3.test:9000/<bucket>/<key>`). */
import { http, HttpResponse } from 'msw';

export const FAKE_S3_ENDPOINT = 'http://s3.test:9000';
export const FAKE_S3_BUCKET = 'loose-test';

export interface FakeS3Object {
  body: Uint8Array;
  contentType: string | null;
}

export interface FakeS3 {
  handlers: ReturnType<typeof http.get>[];
  objects: Map<string, FakeS3Object>;
  /** Every request seen: `METHOD key` plus the Authorization / content-type headers. */
  requests: {
    method: string;
    key: string;
    authorization: string | null;
    contentType: string | null;
  }[];
  /** When set, every request fails with this status (S3 outage / permission error). */
  failWith: number | null;
  reset(): void;
}

function xmlError(code: string, status: number) {
  return new HttpResponse(
    `<?xml version="1.0"?><Error><Code>${code}</Code><Message>${code}</Message></Error>`,
    {
      status,
      headers: { 'content-type': 'application/xml' },
    },
  );
}

export function createFakeS3(bucket = FAKE_S3_BUCKET, endpoint = FAKE_S3_ENDPOINT): FakeS3 {
  const state: FakeS3 = {
    handlers: [],
    objects: new Map(),
    requests: [],
    failWith: null,
    reset() {
      state.objects.clear();
      state.requests.length = 0;
      state.failWith = null;
    },
  };
  const keyOf = (url: string) =>
    decodeURIComponent(new URL(url).pathname.slice(`/${bucket}/`.length));
  const record = (request: Request, key: string) =>
    state.requests.push({
      method: request.method,
      key,
      authorization: request.headers.get('authorization'),
      contentType: request.headers.get('content-type'),
    });

  state.handlers = [
    http.put(`${endpoint}/${bucket}/*`, async ({ request }) => {
      const key = keyOf(request.url);
      record(request, key);
      if (state.failWith) return xmlError('InternalError', state.failWith);
      state.objects.set(key, {
        body: new Uint8Array(await request.arrayBuffer()),
        contentType: request.headers.get('content-type'),
      });
      return new HttpResponse(null, { status: 200, headers: { etag: '"fake-etag"' } });
    }),
    http.get(`${endpoint}/${bucket}/*`, ({ request }) => {
      const key = keyOf(request.url);
      record(request, key);
      if (state.failWith) return xmlError('AccessDenied', state.failWith);
      const obj = state.objects.get(key);
      if (!obj) return xmlError('NoSuchKey', 404);
      const url = new URL(request.url);
      return new HttpResponse(obj.body, {
        status: 200,
        headers: {
          'content-type':
            url.searchParams.get('response-content-type') ??
            obj.contentType ??
            'application/octet-stream',
          'content-length': String(obj.body.byteLength),
          ...(url.searchParams.get('response-content-disposition')
            ? { 'content-disposition': url.searchParams.get('response-content-disposition')! }
            : {}),
        },
      });
    }),
    http.delete(`${endpoint}/${bucket}/*`, ({ request }) => {
      const key = keyOf(request.url);
      record(request, key);
      if (state.failWith) return xmlError('InternalError', state.failWith);
      state.objects.delete(key);
      return new HttpResponse(null, { status: 204 });
    }),
    http.head(`${endpoint}/${bucket}`, ({ request }) => {
      record(request, '');
      return new HttpResponse(null, { status: state.failWith ?? 200 });
    }),
  ];
  return state;
}
