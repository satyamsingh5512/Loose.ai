/** Lightweight Prometheus 0.0.4 registry; intentionally dependency-free. */
export type Labels = Readonly<Record<string, string | number>>;

export const METRIC_NAMES = [
  'loose_http_requests_total',
  'loose_http_request_duration_seconds',
  'loose_errors_total',
  'loose_session_start_seconds',
  'loose_sandbox_boot_seconds',
  'loose_first_token_seconds',
  'loose_turn_duration_seconds',
  'loose_tokens_total',
  'loose_cost_usd_total',
  'loose_ws_connections',
  'loose_ws_messages_total',
  'loose_queue_depth',
  'loose_jobs_total',
  'loose_pr_attempts_total',
  'loose_template_builds_total',
  'loose_sandbox_operations_total',
  'loose_circuit_breaker_open',
  'loose_key_validations_total',
  'loose_webhook_deliveries_total',
  'loose_ssrf_blocked_total',
  'loose_auth_events_total',
  'loose_audit_chain_breaks_total',
  'loose_retention_purged_total',
  'loose_retention_last_success_timestamp_seconds',
  'loose_process_resident_memory_bytes',
  'loose_process_uptime_seconds',
  'loose_nodejs_eventloop_lag_seconds',
] as const;
export type MetricName = (typeof METRIC_NAMES)[number];
export const DEFAULT_DURATION_BUCKETS: readonly number[] = Object.freeze([
  0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300,
]);

export interface Counter {
  inc(labels?: Labels, by?: number): void;
}
export interface Gauge {
  set(value: number, labels?: Labels): void;
  inc(labels?: Labels, by?: number): void;
  dec(labels?: Labels, by?: number): void;
}
export interface Histogram {
  observe(value: number, labels?: Labels): void;
  startTimer(labels?: Labels): () => number;
}
export interface MetricsRegistry {
  readonly enabled: boolean;
  counter(name: MetricName, help: string, labelNames?: readonly string[]): Counter;
  gauge(
    name: MetricName,
    help: string,
    labelNames?: readonly string[],
    collect?: (gauge: Gauge) => Promise<void> | void,
  ): Gauge;
  histogram(
    name: MetricName,
    help: string,
    labelNames?: readonly string[],
    buckets?: readonly number[],
  ): Histogram;
  render(): Promise<string>;
}
export interface CreateMetricsOptions {
  enabled?: boolean;
}

type MetricKind = 'counter' | 'gauge' | 'histogram';
interface MetricState {
  kind: MetricKind;
  help: string;
  labels: readonly string[];
  values: Map<string, number>;
  buckets?: readonly number[];
  collectors?: ((g: Gauge) => Promise<void> | void)[];
}
const esc = (v: string) =>
  v.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('\n', '\\n');
const labelKey = (labels: Labels | undefined, names: readonly string[]) =>
  names.map((n) => String(labels?.[n] ?? '')).join('\u0000');
const labelsFor = (key: string, names: readonly string[]) => {
  if (!names.length) return '';
  const values = key.split('\u0000');
  return `{${names.map((name, i) => `${name}="${esc(values[i] ?? '')}"`).join(',')}}`;
};
function checkLabels(s: MetricState, labels?: Labels) {
  for (const k of Object.keys(labels ?? {}))
    if (!s.labels.includes(k)) throw new Error(`Unknown label ${k}`);
}
function sample(s: MetricState, labels?: Labels) {
  checkLabels(s, labels);
  return labelKey(labels, s.labels);
}

export function createMetricsRegistry(opts: CreateMetricsOptions = {}): MetricsRegistry {
  const enabled = opts.enabled ?? true;
  const states = new Map<MetricName, MetricState>();
  const state = (
    name: MetricName,
    kind: MetricKind,
    help: string,
    labels: readonly string[],
    buckets?: readonly number[],
  ) => {
    let existing = states.get(name);
    if (!existing) {
      existing = {
        kind,
        help,
        labels: [...labels],
        values: new Map(),
        ...(buckets ? { buckets: [...buckets].sort((a, b) => a - b) } : {}),
      };
      states.set(name, existing);
    }
    if (existing.kind !== kind)
      throw new Error(`Metric ${name} was registered as ${existing.kind}`);
    return existing;
  };
  const counter = (name: MetricName, help: string, labels: readonly string[] = []): Counter => {
    const s = state(name, 'counter', help, labels);
    return {
      inc: (l, by = 1) => {
        if (!enabled) return;
        const k = sample(s, l);
        s.values.set(k, (s.values.get(k) ?? 0) + by);
      },
    };
  };
  const gauge = (
    name: MetricName,
    help: string,
    labels: readonly string[] = [],
    collect?: (g: Gauge) => Promise<void> | void,
  ): Gauge => {
    const s = state(name, 'gauge', help, labels);
    const g: Gauge = {
      set: (v, l) => {
        if (!enabled) return;
        s.values.set(sample(s, l), v);
      },
      inc: (l, by = 1) => {
        if (!enabled) return;
        const k = sample(s, l);
        s.values.set(k, (s.values.get(k) ?? 0) + by);
      },
      dec: (l, by = 1) => {
        if (!enabled) return;
        const k = sample(s, l);
        s.values.set(k, (s.values.get(k) ?? 0) - by);
      },
    };
    if (collect && !s.collectors?.includes(collect)) (s.collectors ??= []).push(collect);
    return g;
  };
  const histogram = (
    name: MetricName,
    help: string,
    labels: readonly string[] = [],
    buckets = DEFAULT_DURATION_BUCKETS,
  ): Histogram => {
    const s = state(name, 'histogram', help, labels, buckets);
    return {
      observe: (v, l) => {
        if (!enabled) return;
        const key = sample(s, l);
        for (const b of s.buckets ?? []) {
          if (v <= b) {
            const bk = `${key}\u0001${b}`;
            s.values.set(bk, (s.values.get(bk) ?? 0) + 1);
          }
        }
        const inf = `${key}\u0001+Inf`;
        s.values.set(inf, (s.values.get(inf) ?? 0) + 1);
        const sum = `${key}\u0001sum`;
        s.values.set(sum, (s.values.get(sum) ?? 0) + v);
        const count = `${key}\u0001count`;
        s.values.set(count, (s.values.get(count) ?? 0) + 1);
      },
      startTimer: (l) => {
        const start = process.hrtime.bigint();
        return () => {
          const seconds = Number(process.hrtime.bigint() - start) / 1e9;
          histogram(name, help, labels, buckets).observe(seconds, l);
          return seconds;
        };
      },
    };
  };
  return {
    enabled,
    counter,
    gauge,
    histogram,
    async render() {
      if (!enabled) return '';
      for (const s of states.values())
        for (const collect of s.collectors ?? []) await collect(gaugeFromState(s, enabled));
      const out = ['# Prometheus metrics exported by loose.ai'];
      for (const [name, s] of states) {
        out.push(`# HELP ${name} ${esc(s.help)}`, `# TYPE ${name} ${s.kind}`);
        if (s.kind === 'histogram') {
          const groups = new Set([...s.values.keys()].map((k) => k.split('\u0001')[0] ?? ''));
          for (const group of groups)
            for (const suffix of [...(s.buckets ?? []), '+Inf', 'sum', 'count']) {
              const v = s.values.get(`${group}\u0001${suffix}`) ?? 0;
              const ls =
                suffix === 'sum' || suffix === 'count'
                  ? labelsFor(group, s.labels)
                  : `{${[...s.labels.map((n, i) => `${n}="${esc(group.split('\u0000')[i] ?? '')}"`), `le="${suffix}"`].join(',')}}`;
              out.push(
                `${name}_${suffix === 'sum' || suffix === 'count' ? suffix : 'bucket'}${ls} ${v}`,
              );
            }
        } else
          for (const [key, value] of s.values)
            out.push(`${name}${labelsFor(key, s.labels)} ${value}`);
      }
      return `${out.join('\n')}\n`;
    },
  };
}
function gaugeFromState(s: MetricState, enabled: boolean): Gauge {
  return {
    set(v, l) {
      if (enabled) s.values.set(sample(s, l), v);
    },
    inc(l, by = 1) {
      if (enabled) {
        const k = sample(s, l);
        s.values.set(k, (s.values.get(k) ?? 0) + by);
      }
    },
    dec(l, by = 1) {
      if (enabled) {
        const k = sample(s, l);
        s.values.set(k, (s.values.get(k) ?? 0) - by);
      }
    },
  };
}
