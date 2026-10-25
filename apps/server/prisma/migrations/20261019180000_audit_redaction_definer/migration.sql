-- REAUDIT-007: the runtime role must not be able to erase audit attribution (actorId / ip).
--
-- Before: `loose_app` held UPDATE on "AuditLog", and the guard trigger let any session null
-- "actorId" / "ip" (meant for GDPR redaction). The hash excludes both (so redaction keeps the
-- chain valid), so a compromised runtime credential could hide which administrator / source IP
-- performed an action while verification still answered ok:true.
--
-- After (together with docker/postgres/runtime-role.sql, which revokes table-level UPDATE on
-- "AuditLog" from loose_app and grants UPDATE only on the chain columns legacy sealing writes):
--
-- 1. loose_audit_redact_user(request_id): SECURITY DEFINER (runs as the migrator / table owner),
--    pinned search_path, EXECUTE revoked from PUBLIC. It nulls "actorId" and "ip" of one user's
--    audit rows, and only while that user's account deletion is executing: the DeletionRequest
--    must be kind USER, PENDING, due (scheduledFor <= database clock + 5 min skew), and the caller must hold
--    (or be able to take) the request's execution lock `deletion-exec:<id>` that the deletion
--    sweep holds in its final transaction. The server records a chained `audit.redacted` entry
--    (HMAC-signed, carrying the user's actorDigest) in every affected chain in the same
--    transaction; verifyChain refuses rows whose actorId was removed without such a marker.
-- 2. loose_audit_log_guard (replaced): "action" / "target" / "meta" never change (even in
--    `loose.audit_maintenance` mode, which any session can enter); a chained row's
--    seq / prevHash / hash / actorDigest never change; "actorId" / "ip" may only change to NULL
--    and only when the statement runs as the table owner or a superuser — i.e. inside the
--    definer function above, the owner's own maintenance, or an FK action (`ON DELETE SET NULL`
--    of "actorId" runs as the table owner). Legacy sealing (unchained rows → chain, maintenance
--    mode) is unchanged.
--
-- Hand-written (not managed by Prisma); `prisma migrate diff` does not see triggers/functions.

CREATE OR REPLACE FUNCTION loose_audit_log_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  privileged BOOLEAN;
BEGIN
  IF TG_OP = 'UPDATE' AND (
       NEW."id" IS DISTINCT FROM OLD."id"
       OR NEW."orgId" IS DISTINCT FROM OLD."orgId"
       OR NEW."createdAt" IS DISTINCT FROM OLD."createdAt"
       OR (OLD."chain" IS NOT NULL AND NEW."chain" IS DISTINCT FROM OLD."chain")
       OR (NEW."chain" IS NOT NULL AND NEW."chain" IS DISTINCT FROM COALESCE(NEW."orgId", 'global'))
       OR (NEW."chain" IS NOT NULL AND (NEW."seq" IS NULL OR NEW."prevHash" IS NULL OR NEW."hash" IS NULL))
     ) THEN
    RAISE EXCEPTION 'AuditLog rows are immutable (UPDATE of % identity/time/chain)', OLD."id"
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    -- Content is immutable in every mode.
    IF NEW."action" IS DISTINCT FROM OLD."action"
       OR NEW."target" IS DISTINCT FROM OLD."target"
       OR NEW."meta" IS DISTINCT FROM OLD."meta" THEN
      RAISE EXCEPTION 'AuditLog rows are immutable (UPDATE of % content)', OLD."id"
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- A chained row's position, link, signature and actor digest are fixed once written.
    IF OLD."chain" IS NOT NULL AND (
         NEW."seq" IS DISTINCT FROM OLD."seq"
         OR NEW."prevHash" IS DISTINCT FROM OLD."prevHash"
         OR NEW."hash" IS DISTINCT FROM OLD."hash"
         OR NEW."actorDigest" IS DISTINCT FROM OLD."actorDigest"
       ) THEN
      RAISE EXCEPTION 'AuditLog rows are immutable (UPDATE of % chain fields)', OLD."id"
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Attribution: only redaction (→ NULL), and only as the owner / a superuser.
    IF NEW."actorId" IS DISTINCT FROM OLD."actorId" OR NEW."ip" IS DISTINCT FROM OLD."ip" THEN
      IF (NEW."actorId" IS DISTINCT FROM OLD."actorId" AND NEW."actorId" IS NOT NULL)
         OR (NEW."ip" IS DISTINCT FROM OLD."ip" AND NEW."ip" IS NOT NULL) THEN
        RAISE EXCEPTION 'AuditLog rows are immutable (UPDATE of % attribution)', OLD."id"
          USING ERRCODE = 'insufficient_privilege';
      END IF;
      SELECT (current_user = pg_get_userbyid(c."relowner"))
             OR COALESCE((SELECT r."rolsuper" FROM pg_roles r WHERE r."rolname" = current_user), false)
        INTO privileged
        FROM pg_class c WHERE c."oid" = TG_RELID;
      IF NOT COALESCE(privileged, false) THEN
        RAISE EXCEPTION 'AuditLog attribution of % can only be redacted by loose_audit_redact_user', OLD."id"
          USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
  END IF;

  IF pg_trigger_depth() > 1 OR current_setting('loose.audit_maintenance', true) = 'on' THEN
    IF TG_OP = 'DELETE' THEN
      RETURN OLD;
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'AuditLog rows are immutable (DELETE of %)', OLD."id"
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- Outside maintenance mode even unchained rows keep their chain fields (sealing needs it).
  IF NEW."chain" IS DISTINCT FROM OLD."chain"
     OR NEW."seq" IS DISTINCT FROM OLD."seq"
     OR NEW."prevHash" IS DISTINCT FROM OLD."prevHash"
     OR NEW."hash" IS DISTINCT FROM OLD."hash"
     OR NEW."actorDigest" IS DISTINCT FROM OLD."actorDigest" THEN
    RAISE EXCEPTION 'AuditLog rows are immutable (UPDATE of %)', OLD."id"
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION loose_audit_redact_user(p_request_id TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
  db_now TIMESTAMP(3) := (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC')::TIMESTAMP(3);
  req RECORD;
  n INTEGER;
BEGIN
  IF p_request_id IS NULL OR p_request_id = '' THEN
    RAISE EXCEPTION 'loose_audit_redact_user: invalid arguments' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  -- The execution lock of the deletion sweep (services/governance/deletion.ts `lockPending`).
  -- Advisory locks are re-entrant, so the sweep's own transaction passes; any other session
  -- executing the same request at the same time is refused.
  IF NOT pg_try_advisory_xact_lock(hashtextextended('deletion-exec:' || p_request_id, 0)) THEN
    RAISE EXCEPTION 'loose_audit_redact_user: deletion % is being executed elsewhere', p_request_id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT "kind"::TEXT AS kind, "status"::TEXT AS status, "userId", "scheduledFor"
    INTO req
    FROM "DeletionRequest"
   WHERE "id" = p_request_id
   FOR UPDATE;
  IF NOT FOUND OR req.kind <> 'USER' OR req.status <> 'PENDING' OR req."userId" IS NULL
     OR req."scheduledFor" > db_now + INTERVAL '5 minutes' THEN -- 5 min app/DB clock-skew slack
    RAISE EXCEPTION 'loose_audit_redact_user: % is not a due, pending account deletion', p_request_id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  UPDATE "AuditLog" SET "actorId" = NULL, "ip" = NULL WHERE "actorId" = req."userId";
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END;
$$;

-- Callable only by roles granted explicitly (docker/postgres/runtime-role.sql grants loose_app).
REVOKE ALL ON FUNCTION loose_audit_redact_user(TEXT) FROM PUBLIC;
