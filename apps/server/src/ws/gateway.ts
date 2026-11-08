/**
 * WebSocket gateway (spec §11) on the API's HTTP server at `/ws`.
 *
 * - Auth on upgrade (cookie + Origin check, or PAT bearer) → else `error` LSE-WS-001 + close 4401.
 * - `join_session` checks participation (owner / org ADMIN+) → else LSE-WS-002 + close 4403;
 *   replays the event log after `lastEventId` (gap beyond the retained log → LSE-WS-004,
 *   close 4409 — the client reloads history via REST), then `replay_complete`, then live.
 * - Per-recipient mode filtering: Simple viewers never receive Pro-only events (tool_event,
 *   terminal_output, file lists); see `deliverableFor`.
 * - Heartbeat: server pings every 25 s; no traffic for 60 s → close 4408 (LSE-WS-003).
 * - Limits: frames > 256 KB → close 4413 (LSE-WS-007); > 30 messages / 10 s → close 4429
 *   (LSE-WS-005); invalid messages → `error` LSE-WS-006, connection kept.
 * - `close()` drains: stops accepting upgrades and closes every socket with 1001.
 *
 * Presence is tracked per process (connections served by this instance).
 */
import type { IncomingMessage, Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocket, WebSocketServer, type RawData } from 'ws';
import {
  buildErrorEnvelope,
  buildServerMessage,
  MAX_WS_MESSAGE_BYTES,
  parseClientMessage,
  WS_CLIENT_RATE_LIMIT,
  WS_CLOSE_CODES,
  WS_HEARTBEAT_MS,
  WS_IDLE_TIMEOUT_MS,
  WS_PATH,
  type ClientMessage,
  type ErrorCode,
  type Mode,
  type ServerMessage,
  type ServerMessageType,
  type ServerPayloadInput,
  type SessionParticipantRole,
} from '@loose/shared';
import type { AppContext } from '../context';
import { ClusterCommandForwarder } from '../lib/events/cluster';
import { ClusterPresence, type PresenceEntry } from '../lib/events/presence';
import {
  policyChangeMatches,
  registerRevocationBus,
  revocationMatches,
  RevocationBus,
  type RevocationEvent,
} from '../lib/events/revocations';
import { deliverableFor, type BusEntry } from '../lib/events/sessionEventBus';
import { AppError } from '../lib/errors';
import { decideApproval, viewerMode } from '../services/agentChat.service';
import { runCommand } from '../services/commands.service';
import { invalidateOrgSecurityCache } from '../services/identity/accessPolicy';
import {
  assertTokenScope,
  loadSessionForParticipant,
  type Caller,
} from '../services/sessionLifecycle.service';
import { authenticateUpgrade, revalidateWsCaller } from './auth';

export interface WsGatewayOptions {
  heartbeatMs?: number;
  idleTimeoutMs?: number;
  rateLimit?: { windowMs: number; max: number };
  maxMessageBytes?: number;
  /** How long a successful credential re-validation is reused (P10-SEC-003). */
  credentialCacheMs?: number;
}

interface Conn {
  id: string;
  ws: WebSocket;
  caller: Caller;
  sessionId?: string;
  /** Org of the joined session (REAUDIT-006: `policy_changed` events are org-scoped). */
  orgId?: string;
  mode: Mode;
  /** Mode lock for this viewer (member lock / org policy), if any. */
  locked?: Mode;
  /** Phase 9 (spec §8.18): how this viewer takes part in the joined session. */
  participantRole?: SessionParticipantRole;
  /** Access comes only from a share — losing it disconnects the viewer. */
  viaShare?: boolean;
  /** Participant currently in control of the joined session (null = the owner drives). */
  controllerId?: string | null;
  lastSeq: number;
  lastSeen: number;
  recent: number[];
  unsubscribe?: () => void;
  presenceUnsubscribe?: () => void;
  /** Epoch ms of the last successful credential re-validation (P10-SEC-003). */
  credentialCheckedAt: number;
  /** Inbound frames are handled one at a time, in order (a join must finish first). */
  inbound: Promise<void>;
}

const NO_SESSION = '-';
/** Default freshness of a credential re-validation (P10-SEC-003). */
const CREDENTIAL_CACHE_MS = 5_000;

export class WsGateway {
  readonly #wss: WebSocketServer;
  readonly #conns = new Set<Conn>();
  readonly #bySession = new Map<string, Set<Conn>>();
  /** Sessions with a presence broadcast already scheduled for this tick. */
  readonly #presencePending = new Set<string>();
  readonly #heartbeat: NodeJS.Timeout;
  readonly #opts: Required<WsGatewayOptions>;
  readonly #presenceStore: ClusterPresence;
  readonly #commandForwarder: ClusterCommandForwarder;
  readonly #revocations: RevocationBus;
  readonly #unregisterRevocations: () => void;
  #closing = false;
  #server?: Server;
  readonly #onUpgrade = (req: IncomingMessage, socket: Duplex, head: Buffer) =>
    this.#upgrade(req, socket, head);

  constructor(
    private readonly ctx: AppContext,
    opts: WsGatewayOptions = {},
  ) {
    this.#presenceStore = new ClusterPresence(
      ctx.redis,
      ctx.instanceId,
      ctx.logger,
      ctx.env.SESSION_SECRET,
    );
    this.#commandForwarder = new ClusterCommandForwarder(ctx, (caller, message) =>
      this.#executeAction(caller, message),
    );
    void this.#commandForwarder
      .start()
      .catch((err) => ctx.logger.warn({ err }, 'cluster command relay startup failed'));
    // P10-SEC-003: logout / session delete / PAT revocation close live sockets on every instance.
    this.#revocations = new RevocationBus({
      redis: ctx.redis,
      instanceId: ctx.instanceId,
      logger: ctx.logger,
      secret: ctx.env.SESSION_SECRET,
    });
    this.#revocations.subscribe((event) => this.#onRevocation(event));
    this.#unregisterRevocations = registerRevocationBus(this.#revocations);
    this.#opts = {
      heartbeatMs: opts.heartbeatMs ?? WS_HEARTBEAT_MS,
      idleTimeoutMs: opts.idleTimeoutMs ?? WS_IDLE_TIMEOUT_MS,
      rateLimit: opts.rateLimit ?? { ...WS_CLIENT_RATE_LIMIT },
      maxMessageBytes: opts.maxMessageBytes ?? MAX_WS_MESSAGE_BYTES,
      credentialCacheMs: opts.credentialCacheMs ?? CREDENTIAL_CACHE_MS,
    };
    // ws enforces a hard ceiling (close 1009); our own check below answers with 4413 first.
    this.#wss = new WebSocketServer({ noServer: true, maxPayload: this.#opts.maxMessageBytes * 4 });
    this.#heartbeat = setInterval(() => this.#tick(), this.#opts.heartbeatMs);
    this.#heartbeat.unref();
  }

  get connectionCount(): number {
    return this.#conns.size;
  }

  attach(server: Server): this {
    this.#server = server;
    server.on('upgrade', this.#onUpgrade);
    return this;
  }

  #closed?: Promise<void>;

  /** Idempotent graceful drain. */
  close(): Promise<void> {
    this.#closed ??= this.#close();
    return this.#closed;
  }

  async #close(): Promise<void> {
    this.#closing = true;
    clearInterval(this.#heartbeat);
    this.#server?.off('upgrade', this.#onUpgrade);
    this.#unregisterRevocations();
    for (const c of this.#conns) {
      c.unsubscribe?.();
      c.ws.close(WS_CLOSE_CODES.GOING_AWAY, 'server shutting down');
    }
    await this.#presenceStore.close().catch(() => undefined);
    await this.#commandForwarder.close().catch(() => undefined);
    await this.#revocations.close().catch(() => undefined);
    await new Promise<void>((resolve) => {
      const t = setTimeout(() => {
        for (const c of this.#conns) c.ws.terminate();
        resolve();
      }, 2000);
      t.unref();
      this.#wss.close(() => {
        clearTimeout(t);
        resolve();
      });
    });
  }

  // ---- connection setup ------------------------------------------------------------------

  #upgrade(req: IncomingMessage, socket: Duplex, head: Buffer) {
    let path: string;
    try {
      path = new URL(req.url ?? '/', 'http://localhost').pathname;
    } catch {
      path = '';
    }
    if (path !== WS_PATH) return; // not ours (other upgrade handlers may exist)
    if (this.#closing) {
      socket.destroy();
      return;
    }
    void authenticateUpgrade(this.ctx, req)
      .catch((err: unknown) => {
        this.ctx.logger.warn({ err }, 'ws auth failed');
        return { ok: false as const, reason: 'bad_session' as const };
      })
      .then((auth) => {
        this.#wss.handleUpgrade(req, socket, head, (ws) => {
          if (!auth.ok) {
            // Reason + Origin only (never cookies/tokens). `bad_origin` usually means the web
            // app is served from an origin other than APP_URL.
            this.ctx.logger.warn(
              { code: 'LSE-WS-001', reason: auth.reason, origin: req.headers.origin ?? null },
              'ws upgrade rejected',
            );
            this.#sendRaw(ws, this.#errorMessage(NO_SESSION, 'LSE-WS-001', false));
            ws.close(WS_CLOSE_CODES.UNAUTHORIZED, 'LSE-WS-001');
            return;
          }
          this.#accept(ws, auth.caller);
        });
      });
  }

  #accept(ws: WebSocket, caller: Caller) {
    const conn: Conn = {
      id: `ws_${Math.random().toString(36).slice(2, 12)}`,
      ws,
      caller,
      mode: 'SIMPLE',
      lastSeq: 0,
      lastSeen: Date.now(),
      recent: [],
      credentialCheckedAt: Date.now(),
      inbound: Promise.resolve(),
    };
    this.#conns.add(conn);
    this.ctx.metrics.gauge('loose_ws_connections', 'Open WebSocket connections').inc();
    ws.on('pong', () => (conn.lastSeen = Date.now()));
    // Serialize per connection: clients flush queued messages right after `join_session`,
    // so a `chat_message` must not be dispatched before the (async) join completes.
    ws.on('message', (data, isBinary) => {
      conn.inbound = conn.inbound
        .then(() => this.#onMessage(conn, data, isBinary))
        .catch((err: unknown) => this.ctx.logger.error({ err }, 'ws message handling failed'));
    });
    ws.on('close', () => this.#drop(conn));
    ws.on('error', () => this.#drop(conn));
  }

  #drop(conn: Conn) {
    if (!this.#conns.delete(conn)) return;
    this.ctx.metrics.gauge('loose_ws_connections', 'Open WebSocket connections').dec();
    this.#leave(conn);
  }

  #tick() {
    const now = Date.now();
    for (const c of this.#conns) {
      if (now - c.lastSeen > this.#opts.idleTimeoutMs) {
        c.ws.close(WS_CLOSE_CODES.IDLE_TIMEOUT, 'LSE-WS-003');
        c.ws.terminate();
        this.#drop(c);
        continue;
      }
      if (c.ws.readyState === WebSocket.OPEN) c.ws.ping();
    }
    // P10-SEC-003: catch expiry / out-of-band deletion even on an idle-but-pinging socket.
    void this.#sweepCredentials();
  }

  async #sweepCredentials(): Promise<void> {
    for (const c of [...this.#conns]) {
      if (c.ws.readyState !== WebSocket.OPEN) continue;
      await this.#revalidate(c, 'expired');
    }
  }

  /** Re-validates now and closes the socket when it fails; true while it may continue. */
  async #revalidate(conn: Conn, reason: string): Promise<boolean> {
    const state = await this.#checkCredential(conn);
    if (state === 'ok') {
      conn.credentialCheckedAt = Date.now();
      return true;
    }
    if (state === 'revoked') this.#closeUnauthorized(conn, reason);
    else if (state === 'forbidden') this.#closeForbidden(conn, reason);
    else this.#closeUnverifiable(conn);
    return false;
  }

  /**
   * P10-SEC-003: a credential check that cannot complete (DB error, timeout) is NOT a pass — a
   * transient blip must not keep a revoked socket alive. Callers close such sockets with a
   * retryable code; the client reconnects and the upgrade re-authenticates from scratch.
   */
  async #checkCredential(conn: Conn): Promise<'ok' | 'revoked' | 'forbidden' | 'unavailable'> {
    try {
      // REAUDIT-006: reload the FULL credential (incl. SSO / 2FA assurance) and re-run the org
      // access policy for the joined session; the fresh caller replaces the upgrade-time one,
      // so commands are authorized with live assurance, never the cached rows.
      const result = await revalidateWsCaller(this.ctx, conn.caller, conn.sessionId);
      if (result.state === 'ok') conn.caller = result.caller;
      return result.state;
    } catch (err) {
      this.ctx.logger.warn(
        { err, userId: conn.caller.user.id },
        'ws credential check failed; closing the connection (retryable)',
      );
      return 'unavailable';
    }
  }

  /** Closes a socket whose credential could not be re-verified: close 1013 (try again later). */
  #closeUnverifiable(conn: Conn) {
    if (!this.#conns.has(conn)) return;
    conn.ws.close(WS_CLOSE_CODES.TRY_AGAIN_LATER, 'credential check unavailable');
    this.#drop(conn);
  }

  /** No longer a participant of the joined session (member removed, IP allowlist): 4403. */
  #closeForbidden(conn: Conn, reason: string) {
    if (!this.#conns.has(conn)) return;
    this.ctx.logger.warn(
      { code: 'LSE-WS-002', reason, userId: conn.caller.user.id },
      'ws connection access revoked',
    );
    this.#sendError(conn, 'LSE-WS-002');
    conn.ws.close(WS_CLOSE_CODES.FORBIDDEN, 'LSE-WS-002');
    this.#drop(conn);
  }

  /** Closes a socket whose credential is gone: `error` LSE-WS-001 + close 4401. */
  #closeUnauthorized(conn: Conn, reason: string) {
    if (!this.#conns.has(conn)) return;
    this.ctx.logger.warn(
      { code: 'LSE-WS-001', reason, userId: conn.caller.user.id },
      'ws connection revoked',
    );
    this.#sendError(conn, 'LSE-WS-001');
    conn.ws.close(WS_CLOSE_CODES.UNAUTHORIZED, 'LSE-WS-001');
    this.#drop(conn);
  }

  /** A revocation event (this instance or a peer): close every socket it covers. */
  #onRevocation(event: RevocationEvent) {
    if (event.reason === 'policy_changed' && event.orgId) {
      // REAUDIT-006: peers must not keep serving the old policy from their 5 s cache.
      invalidateOrgSecurityCache(this.ctx, event.orgId);
    }
    for (const c of [...this.#conns]) {
      if (
        policyChangeMatches(event, {
          userId: c.caller.user.id,
          orgIds: [c.orgId, c.caller.apiToken?.orgId],
        })
      ) {
        // Re-validate immediately, serialized with the socket's inbound frames: a command that
        // arrives after the event waits for (and is refused by) this check.
        c.credentialCheckedAt = 0;
        c.inbound = c.inbound
          .then(async () => {
            if (this.#conns.has(c)) await this.#revalidate(c, event.reason);
          })
          .catch((err: unknown) => this.ctx.logger.error({ err }, 'ws policy re-check failed'));
        continue;
      }
      const matches = revocationMatches(event, {
        userId: c.caller.user.id,
        authSessionId: c.caller.authSession?.id,
        apiTokenId: c.caller.apiToken?.id,
      });
      if (matches) this.#closeUnauthorized(c, event.reason);
    }
  }

  /**
   * Re-validates the connection's credential before a state-changing command, reusing a
   * successful check for `credentialCacheMs`.
   */
  async #assertCredentialFresh(conn: Conn): Promise<boolean> {
    if (Date.now() - conn.credentialCheckedAt < this.#opts.credentialCacheMs) return true;
    return this.#revalidate(conn, 'revoked');
  }

  // ---- sending -----------------------------------------------------------------------------

  #sendRaw(ws: WebSocket, msg: ServerMessage) {
    if (ws.readyState !== WebSocket.OPEN) return;
    this.ctx.metrics
      .counter('loose_ws_messages_total', 'WebSocket messages', ['direction'])
      .inc({ direction: 'out' });
    ws.send(JSON.stringify(msg));
  }

  #direct<T extends ServerMessageType>(
    conn: Conn,
    type: T,
    payload: ServerPayloadInput<T>,
    sessionId?: string,
  ) {
    this.#sendRaw(
      conn.ws,
      buildServerMessage(type, sessionId ?? conn.sessionId ?? NO_SESSION, 0, payload),
    );
  }

  #errorMessage(
    sessionId: string,
    code: ErrorCode,
    recoverable: boolean,
    err?: AppError,
  ): ServerMessage {
    const envelope = err
      ? err.toEnvelope(`ws_${Date.now().toString(36)}`, false)
      : buildErrorEnvelope(code, { requestId: `ws_${Date.now().toString(36)}` });
    return buildServerMessage('error', sessionId, 0, { error: envelope.error, recoverable });
  }

  #sendError(conn: Conn, code: ErrorCode, opts: { sessionId?: string; err?: AppError } = {}) {
    this.#sendRaw(
      conn.ws,
      this.#errorMessage(opts.sessionId ?? conn.sessionId ?? NO_SESSION, code, true, opts.err),
    );
  }

  /**
   * `live` is false while replaying the event log: historical `share_updated` /
   * `control_changed` entries describe the past, and the connection's own role and
   * controller were already read from the database during the join.
   */
  #deliver(conn: Conn, entry: BusEntry, live = true) {
    const msg = deliverableFor(entry, conn.mode);
    if (!msg || msg.seq <= conn.lastSeq) return;
    conn.lastSeq = msg.seq;
    // Shared sessions (spec §8.18): a viewer whose share was revoked is dropped BEFORE the
    // message goes out, so they never learn who else the session is shared with.
    if (live && msg.type === 'share_updated' && conn.sessionId) {
      const mine = msg.payload.collaborators.find((c) => c.userId === conn.caller.user.id);
      if (conn.viaShare && !mine) {
        this.#sendError(conn, 'LSE-WS-002');
        conn.ws.close(WS_CLOSE_CODES.FORBIDDEN, 'LSE-WS-002');
        this.#drop(conn);
        return;
      }
      if (conn.viaShare && mine) {
        conn.participantRole = mine.role === 'CO_EDITOR' ? 'co_editor' : 'viewer';
      }
      this.#presenceSoon(conn.sessionId);
    }
    this.#sendRaw(conn.ws, msg);
    if (live && msg.type === 'control_changed' && conn.sessionId) {
      conn.controllerId = msg.payload.controllerId;
      // A take-over switches the session to Pro; a locked viewer stays where they are.
      conn.mode = conn.locked ?? msg.payload.mode;
      this.#presenceSoon(conn.sessionId);
    }
  }

  // ---- inbound -----------------------------------------------------------------------------

  async #onMessage(conn: Conn, data: RawData, isBinary: boolean) {
    conn.lastSeen = Date.now();
    this.ctx.metrics
      .counter('loose_ws_messages_total', 'WebSocket messages', ['direction'])
      .inc({ direction: 'in' });
    const bytes = Array.isArray(data)
      ? data.reduce((n, b) => n + b.length, 0)
      : data instanceof ArrayBuffer
        ? data.byteLength
        : data.length;
    if (bytes > this.#opts.maxMessageBytes) {
      this.#sendError(conn, 'LSE-WS-007');
      conn.ws.close(WS_CLOSE_CODES.MESSAGE_TOO_LARGE, 'LSE-WS-007');
      return;
    }
    const now = Date.now();
    conn.recent = conn.recent.filter((t) => now - t < this.#opts.rateLimit.windowMs);
    conn.recent.push(now);
    if (conn.recent.length > this.#opts.rateLimit.max) {
      this.#sendError(conn, 'LSE-WS-005');
      conn.ws.close(WS_CLOSE_CODES.RATE_LIMITED, 'LSE-WS-005');
      return;
    }
    if (isBinary) {
      this.#sendError(conn, 'LSE-WS-006');
      return;
    }
    const text = Array.isArray(data)
      ? Buffer.concat(data).toString('utf8')
      : Buffer.from(data as ArrayBuffer).toString('utf8');
    const parsed = parseClientMessage(text);
    if (!parsed.success) {
      this.#sendError(conn, parsed.error === 'too_large' ? 'LSE-WS-007' : 'LSE-WS-006');
      return;
    }
    try {
      await this.#dispatch(conn, parsed.data);
    } catch (err) {
      const appErr = err instanceof AppError ? err : new AppError('LSE-SYS-001', { cause: err });
      if (!(err instanceof AppError))
        this.ctx.logger.error({ err, type: parsed.data.type }, 'ws handler failed');
      this.#sendError(conn, appErr.code, { sessionId: parsed.data.sessionId, err: appErr });
    }
  }

  #requireJoined(conn: Conn, msg: ClientMessage): string {
    if (!conn.sessionId || conn.sessionId !== msg.sessionId) {
      throw new AppError('LSE-WS-002', { devMessage: 'Join the session first' });
    }
    return conn.sessionId;
  }

  async #dispatch(conn: Conn, msg: ClientMessage) {
    switch (msg.type) {
      case 'ping':
        this.#direct(conn, 'pong', {}, msg.sessionId);
        return;
      case 'join_session':
        // P10-SEC-003: a socket may only (re)join while its credential is still valid.
        if (!(await this.#assertCredentialFresh(conn))) return;
        await this.#join(conn, msg.sessionId, msg.payload.lastEventId ?? 0);
        return;
      case 'leave_session':
        this.#leave(conn);
        return;
      default:
        this.#requireJoined(conn, msg);
    }
    // P10-SEC-003: every state-changing command re-checks the backing session / API token.
    if (!(await this.#assertCredentialFresh(conn))) return;
    const remote = await this.#commandForwarder.forwardIfRemote(conn.caller, msg);
    const result = remote.forwarded ? remote.value : await this.#executeAction(conn.caller, msg);
    if (msg.type === 'set_mode' && (result === 'SIMPLE' || result === 'PRO')) {
      for (const c of this.#bySession.get(msg.sessionId) ?? []) c.mode = c.locked ?? result;
    }
  }

  /** Executes a joined command locally, or on behalf of a Redis-forwarded peer. */
  async #executeAction(caller: Caller, msg: ClientMessage) {
    const agent = this.ctx.agent;
    switch (msg.type) {
      case 'chat_message':
        return agent.sendMessage(caller, msg.sessionId, {
          content: msg.payload.content,
          clientMessageId: msg.payload.clientMessageId,
          ...(msg.payload.attachments ? { attachments: msg.payload.attachments } : {}),
          ...(msg.payload.plan ? { plan: true } : {}),
        });
      case 'interrupt':
        return agent.interrupt(caller, msg.sessionId);
      case 'stop_session':
        return agent.stop(caller, msg.sessionId);
      case 'approval_response':
        return decideApproval(this.ctx, caller, msg.sessionId, msg.payload.approvalId, {
          decision: msg.payload.decision,
          ...(msg.payload.reason ? { reason: msg.payload.reason } : {}),
          ...(msg.payload.plan ? { plan: msg.payload.plan } : {}),
        });
      case 'set_mode':
        return agent.setMode(caller, msg.sessionId, msg.payload.mode);
      case 'set_model':
        return agent.setModel(caller, msg.sessionId, msg.payload.model);
      case 'rewind':
        return agent.rewind(caller, msg.sessionId, msg.payload.checkpointId, msg.payload.scope);
      case 'slash_command':
        return runCommand(this.ctx, caller, msg.sessionId, {
          command: msg.payload.command,
          ...(msg.payload.args !== undefined ? { args: msg.payload.args } : {}),
        });
    }
  }

  async #join(conn: Conn, sessionId: string, lastEventId: number) {
    let mode: Mode;
    let locked: Mode | undefined;
    let running = false;
    let participantRole: SessionParticipantRole;
    let viaShare = false;
    let controllerId: string | null = null;
    let orgId: string;
    try {
      assertTokenScope(conn.caller, 'read');
      const access = await loadSessionForParticipant(this.ctx, conn.caller, sessionId);
      const org = await this.ctx.prisma.organization.findUniqueOrThrow({
        where: { id: access.session.project.orgId },
      });
      orgId = org.id;
      mode = viewerMode(access.session, access.membership, org);
      const asOther = viewerMode(
        { mode: access.session.mode === 'PRO' ? 'SIMPLE' : 'PRO' },
        access.membership,
        org,
      );
      locked = asOther === mode ? mode : undefined;
      running = access.session.status === 'RUNNING';
      participantRole = access.participantRole;
      viaShare = access.collaboratorRole !== null;
      controllerId = access.session.controllerId;
    } catch (err) {
      if (!(err instanceof AppError)) this.ctx.logger.warn({ err, sessionId }, 'ws join failed');
      this.#sendError(conn, 'LSE-WS-002', { sessionId });
      conn.ws.close(WS_CLOSE_CODES.FORBIDDEN, 'LSE-WS-002');
      return;
    }
    this.#leave(conn);
    conn.sessionId = sessionId;
    conn.orgId = orgId;
    conn.mode = mode;
    conn.locked = locked;
    conn.participantRole = participantRole;
    conn.viaShare = viaShare;
    conn.controllerId = controllerId;
    conn.lastSeq = lastEventId;
    const bus = this.ctx.sessionEvents;
    const pending: BusEntry[] = [];
    let replaying = true;
    conn.unsubscribe = bus.subscribe(sessionId, (message, audience) => {
      if (replaying) pending.push({ message, audience });
      else this.#deliver(conn, { message, audience });
    });
    let set = this.#bySession.get(sessionId);
    if (!set) {
      set = new Set();
      this.#bySession.set(sessionId, set);
    }
    set.add(conn);
    await bus.ready?.(sessionId);
    const replay = await bus.replay(sessionId, lastEventId);
    if (lastEventId > 0 && !replay.complete) {
      this.#sendError(conn, 'LSE-WS-004', { sessionId });
      conn.ws.close(WS_CLOSE_CODES.REPLAY_GAP, 'LSE-WS-004');
      this.#leave(conn);
      return;
    }
    for (const e of replay.entries) this.#deliver(conn, e, false);
    this.#direct(conn, 'replay_complete', { lastSeq: replay.lastSeq });
    replaying = false;
    for (const e of pending) this.#deliver(conn, e);
    conn.presenceUnsubscribe = this.#presenceStore.subscribe(
      sessionId,
      () => void this.#clusterPresence(sessionId),
    );
    await this.#presenceStore.ready();
    void this.#presenceStore.join(sessionId, conn.id, this.#presenceEntry(conn));
    this.#presence(sessionId);
    if (running) void this.ctx.agent.ensureRuntime(sessionId);
  }

  #leave(conn: Conn) {
    const id = conn.sessionId;
    conn.unsubscribe?.();
    conn.unsubscribe = undefined;
    conn.presenceUnsubscribe?.();
    conn.presenceUnsubscribe = undefined;
    if (id) void this.#presenceStore.leave(id, conn.id);
    conn.sessionId = undefined;
    conn.orgId = undefined;
    conn.participantRole = undefined;
    conn.viaShare = undefined;
    conn.controllerId = undefined;
    if (!id) return;
    const set = this.#bySession.get(id);
    set?.delete(conn);
    if (set && set.size === 0) this.#bySession.delete(id);
    else this.#presence(id);
  }

  #presence(sessionId: string) {
    const conns = [...(this.#bySession.get(sessionId) ?? [])];
    const controllerId = conns.find((c) => c.controllerId != null)?.controllerId ?? null;
    const users = new Map<string, ServerPayloadInput<'presence'>['users'][number]>();
    for (const c of conns) {
      users.set(c.caller.user.id, {
        id: c.caller.user.id,
        name: c.caller.user.name,
        avatarUrl: c.caller.user.avatarUrl,
        ...(c.participantRole ? { role: c.participantRole } : {}),
        mode: c.mode,
        controller: controllerId !== null && controllerId === c.caller.user.id,
      });
    }
    for (const c of conns) this.#direct(c, 'presence', { users: [...users.values()] }, sessionId);
  }

  #presenceEntry(conn: Conn): PresenceEntry {
    return {
      id: conn.caller.user.id,
      name: conn.caller.user.name,
      avatarUrl: conn.caller.user.avatarUrl,
      ...(conn.participantRole ? { role: conn.participantRole } : {}),
      mode: conn.mode,
      controller: conn.controllerId === conn.caller.user.id,
    };
  }

  async #clusterPresence(sessionId: string) {
    const users = await this.#presenceStore.list(sessionId).catch(() => []);
    for (const c of this.#bySession.get(sessionId) ?? [])
      this.#direct(c, 'presence', { users }, sessionId);
  }
  /**
   * Coalesce presence broadcasts: `share_updated` / `control_changed` reach every connection
   * of a session, and each one would otherwise trigger its own fan-out.
   */
  #presenceSoon(sessionId: string) {
    if (this.#presencePending.has(sessionId)) return;
    this.#presencePending.add(sessionId);
    setTimeout(() => {
      this.#presencePending.delete(sessionId);
      if (this.#bySession.has(sessionId)) this.#presence(sessionId);
    }, 0).unref();
  }
}

export function attachWsGateway(
  server: Server,
  ctx: AppContext,
  opts?: WsGatewayOptions,
): WsGateway {
  return new WsGateway(ctx, opts).attach(server);
}
