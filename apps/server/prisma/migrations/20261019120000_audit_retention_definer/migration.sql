-- P10-SEC-006-R2 (REAUDIT-004): the API/worker role must not be able to DELETE audit rows.
--
-- The AuditLog guard trigger permits DELETE inside a `loose.audit_maintenance` transaction, but any
-- session can set that custom GUC, and verifyChain cannot notice a deleted chain *tail* (it has no
-- external record of the expected head). So the runtime role (`loose_app`, see
-- docker/postgres/runtime-role.sql) gets no DELETE privilege on "AuditLog" at all, and retention
-- deletes only through the two SECURITY DEFINER functions below. They run as the migrator (table
-- owner) and validate everything themselves, so whoever can call them can still only remove:
--
--   * loose_audit_purge_prefix: the oldest prefix (seq <= p_through) of ONE org's chain, and only
--     after a chained `audit.retention_purged` marker announcing exactly that prefix (and its
--     anchor hash) was appended after it; every removed row must be older than the marker's cutoff,
--     and that cutoff must be at least the minimum audit retention (30 days, RETENTION_LIMITS
--     .auditLog.min; 5 minutes of clock-skew slack) before the database clock. The marker and every newer row, i.e. the current
--     tail, are never deletable. A forged marker cannot carry a valid HMAC (the key is not in the
--     database), so it breaks verification itself.
--   * loose_audit_purge_legacy: unchained pre-cutover rows of one org older than the same bounds.
--     Unchained rows written after the cutover get createdAt >= cutover from the insert guard
--     (20261019001500_audit_insert_guard), so evidence of a forged row cannot be removed this way.
--
-- Hand-written (not managed by Prisma); `prisma migrate diff` does not see functions.

CREATE OR REPLACE FUNCTION loose_audit_purge_prefix(p_org TEXT, p_through INTEGER, p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  db_now TIMESTAMP(3) := (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC')::TIMESTAMP(3);
  marker RECORD;
  marker_cutoff TIMESTAMP(3);
  anchor_hash TEXT;
  n INTEGER;
BEGIN
  IF p_org IS NULL OR p_org = 'global' OR p_through IS NULL OR p_through < 1
     OR p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
    RAISE EXCEPTION 'loose_audit_purge_prefix: invalid arguments' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(p_org, 0));

  IF NOT EXISTS (SELECT 1 FROM "AuditLog" WHERE "chain" = p_org AND "seq" <= p_through) THEN
    RETURN 0; -- nothing (left) to purge
  END IF;

  SELECT "seq", "meta" INTO marker
  FROM "AuditLog"
  WHERE "chain" = p_org
    AND "orgId" = p_org
    AND "action" = 'audit.retention_purged'
    AND "seq" > p_through
    AND "hash" IS NOT NULL
    AND "meta" ->> 'purgedThroughSeq' = p_through::TEXT
  ORDER BY "seq" DESC
  LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'loose_audit_purge_prefix: no retention marker announces seq <= % of chain %', p_through, p_org
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  BEGIN
    marker_cutoff := ((marker."meta" ->> 'cutoff')::TIMESTAMPTZ AT TIME ZONE 'UTC')::TIMESTAMP(3);
  EXCEPTION WHEN others THEN
    marker_cutoff := NULL;
  END;
  -- 5 minutes of slack for clock skew between the app host and the database.
  IF marker_cutoff IS NULL OR marker_cutoff > db_now - INTERVAL '30 days' + INTERVAL '5 minutes' THEN
    RAISE EXCEPTION 'loose_audit_purge_prefix: cutoff of chain % is inside the minimum retention', p_org
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  SELECT "hash" INTO anchor_hash FROM "AuditLog" WHERE "chain" = p_org AND "seq" = p_through;
  IF anchor_hash IS NULL OR anchor_hash IS DISTINCT FROM (marker."meta" ->> 'anchorHash') THEN
    RAISE EXCEPTION 'loose_audit_purge_prefix: anchor of chain % does not match the marker', p_org
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF EXISTS (
    SELECT 1 FROM "AuditLog"
    WHERE "chain" = p_org AND "seq" <= p_through AND "createdAt" >= marker_cutoff
  ) THEN
    RAISE EXCEPTION 'loose_audit_purge_prefix: prefix of chain % has rows newer than the cutoff', p_org
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  PERFORM set_config('loose.audit_maintenance', 'on', true);
  WITH doomed AS (
    SELECT "id" FROM "AuditLog"
    WHERE "chain" = p_org AND "seq" <= p_through
    ORDER BY "seq" ASC
    LIMIT p_limit
  )
  DELETE FROM "AuditLog" a USING doomed WHERE a."id" = doomed."id";
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM set_config('loose.audit_maintenance', 'off', true);
  RETURN n;
END;
$$;

CREATE OR REPLACE FUNCTION loose_audit_purge_legacy(p_org TEXT, p_cutoff TIMESTAMP(3), p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  db_now TIMESTAMP(3) := (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC')::TIMESTAMP(3);
  cutover TIMESTAMP(3);
  bound TIMESTAMP(3);
  n INTEGER;
BEGIN
  IF p_org IS NULL OR p_cutoff IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
    RAISE EXCEPTION 'loose_audit_purge_legacy: invalid arguments' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT "cutoverAt" INTO cutover FROM "AuditChainCutover" WHERE "id" = 'singleton';
  IF cutover IS NULL THEN
    RETURN 0; -- no marker: no unchained row counts as legacy (fail closed, like verifyChain)
  END IF;
  bound := LEAST(p_cutoff, cutover, db_now - INTERVAL '30 days');

  PERFORM set_config('loose.audit_maintenance', 'on', true);
  WITH doomed AS (
    SELECT "id" FROM "AuditLog"
    WHERE "orgId" = p_org AND "chain" IS NULL AND "createdAt" < bound
    LIMIT p_limit
  )
  DELETE FROM "AuditLog" a USING doomed WHERE a."id" = doomed."id";
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM set_config('loose.audit_maintenance', 'off', true);
  RETURN n;
END;
$$;

-- Callable only by roles granted explicitly (docker/postgres/runtime-role.sql grants loose_app).
REVOKE ALL ON FUNCTION loose_audit_purge_prefix(TEXT, INTEGER, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION loose_audit_purge_legacy(TEXT, TIMESTAMP(3), INTEGER) FROM PUBLIC;
