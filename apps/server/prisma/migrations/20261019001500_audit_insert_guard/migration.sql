-- P10-SEC-006 (backdating): verification treats an unchained AuditLog row as pre-Phase-10 legacy
-- history when its "createdAt" predates the "AuditChainCutover" marker. "createdAt" was writable by
-- the application role, so a forged unchained row could be backdated past the cutover (or an
-- unchained row's "createdAt" edited inside a `loose.audit_maintenance` transaction, which the app
-- role can open itself) and verification would still answer ok:true. Hand-written (not managed by
-- Prisma); `prisma migrate diff` does not see triggers.
--
-- 1. BEFORE INSERT: an unchained row always gets the database clock (never earlier than the
--    cutover), so no new row can pose as legacy. A chained row must live in the chain of its own
--    org ('global' for user-level events) and carry its seq/prevHash/hash, so it cannot hide
--    outside the chain verification walks.
--    There is deliberately no `loose.audit_maintenance` bypass for this (any session can set it).
-- 2. BEFORE UPDATE (replaces loose_audit_log_guard): "id", "orgId" and "createdAt" never change and
--    a chained row never leaves or switches its chain, even in maintenance mode or from FK actions
--    (legacy sealing only moves rows from no chain into their org's chain; retention only deletes;
--    FK actions only null "actorId"). The rest of the original rules are unchanged.

CREATE OR REPLACE FUNCTION loose_audit_log_insert_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  cutover TIMESTAMP(3);
BEGIN
  IF NEW."chain" IS NULL THEN
    SELECT "cutoverAt" INTO cutover FROM "AuditChainCutover" WHERE "id" = 'singleton';
    -- Prisma stores DateTime as UTC in timestamp columns.
    NEW."createdAt" := GREATEST(
      (CURRENT_TIMESTAMP(3) AT TIME ZONE 'UTC')::TIMESTAMP(3),
      COALESCE(cutover, '-infinity'::TIMESTAMP(3))
    );
  ELSIF NEW."chain" IS DISTINCT FROM COALESCE(NEW."orgId", 'global') THEN
    RAISE EXCEPTION 'AuditLog row % must be chained to %, not %',
      NEW."id", COALESCE(NEW."orgId", 'global'), NEW."chain"
      USING ERRCODE = 'check_violation';
  ELSIF NEW."seq" IS NULL OR NEW."prevHash" IS NULL OR NEW."hash" IS NULL THEN
    RAISE EXCEPTION 'AuditLog row % is chained but has no seq/prevHash/hash', NEW."id"
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "AuditLog_insert_guard"
  BEFORE INSERT ON "AuditLog"
  FOR EACH ROW EXECUTE FUNCTION loose_audit_log_insert_guard();

CREATE OR REPLACE FUNCTION loose_audit_log_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
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
  IF NEW."action" IS DISTINCT FROM OLD."action"
     OR NEW."target" IS DISTINCT FROM OLD."target"
     OR NEW."meta" IS DISTINCT FROM OLD."meta"
     OR NEW."chain" IS DISTINCT FROM OLD."chain"
     OR NEW."seq" IS DISTINCT FROM OLD."seq"
     OR NEW."prevHash" IS DISTINCT FROM OLD."prevHash"
     OR NEW."hash" IS DISTINCT FROM OLD."hash"
     OR NEW."actorDigest" IS DISTINCT FROM OLD."actorDigest"
     OR (NEW."actorId" IS DISTINCT FROM OLD."actorId" AND NEW."actorId" IS NOT NULL)
     OR (NEW."ip" IS DISTINCT FROM OLD."ip" AND NEW."ip" IS NOT NULL) THEN
    RAISE EXCEPTION 'AuditLog rows are immutable (UPDATE of %)', OLD."id"
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$;
