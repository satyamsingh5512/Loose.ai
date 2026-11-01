-- Phase 10 audit fixes (fix-identity): P10-SEC-002, P10-SEC-010, P10-SEC-014.

-- P10-SEC-002: PATs remember the assurance of the session that minted them.
ALTER TABLE "ApiToken" ADD COLUMN "ssoConnectionId" TEXT;
ALTER TABLE "ApiToken" ADD COLUMN "mfaVerifiedAt" TIMESTAMP(3);

-- P10-SEC-014: SCIM tokens expire. Existing tokens get one year from their creation.
ALTER TABLE "ScimToken" ADD COLUMN "expiresAt" TIMESTAMP(3);
UPDATE "ScimToken" SET "expiresAt" = "createdAt" + INTERVAL '365 days' WHERE "expiresAt" IS NULL;

-- P10-SEC-010: a domain may be verified by one org only, enforced by the database.
ALTER TABLE "OrgDomain" ADD COLUMN "verifiedDomain" TEXT;
-- Backfill: if (pre-fix) several orgs verified the same domain, the earliest verification keeps it
-- and the others are reset to pending.
WITH ranked AS (
  SELECT "id", ROW_NUMBER() OVER (PARTITION BY "domain" ORDER BY "verifiedAt" ASC, "id" ASC) AS rn
  FROM "OrgDomain"
  WHERE "verifiedAt" IS NOT NULL
)
UPDATE "OrgDomain" d SET "verifiedAt" = NULL FROM ranked r WHERE d."id" = r."id" AND r.rn > 1;
UPDATE "OrgDomain" SET "verifiedDomain" = "domain" WHERE "verifiedAt" IS NOT NULL;
CREATE UNIQUE INDEX "OrgDomain_verifiedDomain_key" ON "OrgDomain"("verifiedDomain");
