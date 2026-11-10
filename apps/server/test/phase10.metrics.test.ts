import { describe, expect, it } from 'vitest';
import { createMetricsRegistry } from '../src/lib/metrics';

describe('Phase 10 metrics registry', () => {
  it('renders counters, gauges and Prometheus histogram buckets', async () => {
    const metrics = createMetricsRegistry();
    metrics
      .counter('loose_http_requests_total', 'requests', ['method', 'status'])
      .inc({ method: 'GET', status: 200 });
    metrics.gauge('loose_ws_connections', 'connections').set(2);
    metrics
      .histogram('loose_http_request_duration_seconds', 'latency', ['method'])
      .observe(0.2, { method: 'GET' });
    const body = await metrics.render();
    expect(body).toContain('loose_http_requests_total{method="GET",status="200"} 1');
    expect(body).toContain('loose_ws_connections 2');
    expect(body).toContain('loose_http_request_duration_seconds_bucket{method="GET",le="0.25"} 1');
  });
  it('returns the same metric and rejects labels outside its contract', () => {
    const metrics = createMetricsRegistry();
    const a = metrics.counter('loose_errors_total', 'errors', ['code']);
    const b = metrics.counter('loose_errors_total', 'ignored help', ['code']);
    a.inc({ code: 'LSE-SYS-001' });
    b.inc({ code: 'LSE-SYS-001' });
    expect(() => a.inc({ source: 'http' })).toThrow('Unknown label source');
  });
});
