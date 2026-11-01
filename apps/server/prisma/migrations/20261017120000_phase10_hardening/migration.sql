-- CreateEnum
CREATE TYPE "SsoProtocol" AS ENUM ('OIDC', 'SAML');

-- CreateEnum
CREATE TYPE "DataExportKind" AS ENUM ('USER', 'ORG');

-- CreateEnum
CREATE TYPE "DataExportStatus" AS ENUM ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "DeletionKind" AS ENUM ('USER', 'ORG');

-- CreateEnum
CREATE TYPE "DeletionStatus" AS ENUM ('PENDING', 'CANCELLED', 'COMPLETED', 'FAILED');

-- AlterTable
ALTER TABLE "AuditLog" ADD COLUMN     "actorDigest" TEXT,
ADD COLUMN     "chain" TEXT,
ADD COLUMN     "hash" TEXT,
ADD COLUMN     "prevHash" TEXT,
ADD COLUMN     "seq" INTEGER;

-- AlterTable
ALTER TABLE "AuthSession" ADD COLUMN     "mfaVerifiedAt" TIMESTAMP(3),
ADD COLUMN     "ssoConnectionId" TEXT,
ADD COLUMN     "ssoOrgId" TEXT;

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "deletionScheduledAt" TIMESTAMP(3),
ADD COLUMN     "featureFlags" JSONB NOT NULL DEFAULT '{}',
ADD COLUMN     "ipAllowlist" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "ipAllowlistEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "requireAdmin2fa" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "Project" ADD COLUMN     "appliedPolicyPacks" JSONB NOT NULL DEFAULT '[]';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "deletionScheduledAt" TIMESTAMP(3),
ADD COLUMN     "totpEnabledAt" TIMESTAMP(3),
ADD COLUMN     "totpLastStep" INTEGER,
ADD COLUMN     "totpPendingSecretEnc" BYTEA,
ADD COLUMN     "totpSecretEnc" BYTEA;

-- CreateTable
CREATE TABLE "SsoConnection" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "protocol" "SsoProtocol" NOT NULL DEFAULT 'OIDC',
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "issuer" TEXT NOT NULL DEFAULT '',
    "clientId" TEXT NOT NULL DEFAULT '',
    "clientSecretEnc" BYTEA,
    "metadata" JSONB,
    "samlEntityId" TEXT,
    "samlSsoUrl" TEXT,
    "samlCertificate" TEXT,
    "defaultRole" "Role" NOT NULL DEFAULT 'MEMBER',
    "jitProvisioning" BOOLEAN NOT NULL DEFAULT true,
    "enforce" BOOLEAN NOT NULL DEFAULT false,
    "allowOwnerBypass" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SsoConnection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SsoIdentity" (
    "id" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SsoIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrgDomain" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "verificationToken" TEXT NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrgDomain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimToken" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "createdById" TEXT,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScimToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimIdentity" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "externalId" TEXT,
    "userName" TEXT NOT NULL,
    "displayName" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "attributes" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScimIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimGroup" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "externalId" TEXT,
    "displayName" TEXT NOT NULL,
    "role" "Role",
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScimGroup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimGroupMember" (
    "id" TEXT NOT NULL,
    "groupId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScimGroupMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TotpRecoveryCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TotpRecoveryCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DataExport" (
    "id" TEXT NOT NULL,
    "kind" "DataExportKind" NOT NULL,
    "status" "DataExportStatus" NOT NULL DEFAULT 'PENDING',
    "orgId" TEXT,
    "requestedById" TEXT NOT NULL,
    "storageKey" TEXT,
    "bytes" INTEGER,
    "error" TEXT,
    "expiresAt" TIMESTAMP(3),
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DataExport_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DeletionRequest" (
    "id" TEXT NOT NULL,
    "kind" "DeletionKind" NOT NULL,
    "status" "DeletionStatus" NOT NULL DEFAULT 'PENDING',
    "userId" TEXT,
    "orgId" TEXT,
    "requestedById" TEXT,
    "scheduledFor" TIMESTAMP(3) NOT NULL,
    "cancelledAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DeletionRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PolicyPack" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "version" INTEGER NOT NULL DEFAULT 1,
    "rules" JSONB NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PolicyPack_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SsoConnection_orgId_key" ON "SsoConnection"("orgId");

-- CreateIndex
CREATE INDEX "SsoIdentity_userId_idx" ON "SsoIdentity"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "SsoIdentity_connectionId_subject_key" ON "SsoIdentity"("connectionId", "subject");

-- CreateIndex
CREATE INDEX "OrgDomain_domain_idx" ON "OrgDomain"("domain");

-- CreateIndex
CREATE UNIQUE INDEX "OrgDomain_orgId_domain_key" ON "OrgDomain"("orgId", "domain");

-- CreateIndex
CREATE UNIQUE INDEX "ScimToken_hash_key" ON "ScimToken"("hash");

-- CreateIndex
CREATE INDEX "ScimToken_orgId_idx" ON "ScimToken"("orgId");

-- CreateIndex
CREATE INDEX "ScimIdentity_orgId_externalId_idx" ON "ScimIdentity"("orgId", "externalId");

-- CreateIndex
CREATE UNIQUE INDEX "ScimIdentity_orgId_userId_key" ON "ScimIdentity"("orgId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "ScimIdentity_orgId_userName_key" ON "ScimIdentity"("orgId", "userName");

-- CreateIndex
CREATE UNIQUE INDEX "ScimGroup_orgId_displayName_key" ON "ScimGroup"("orgId", "displayName");

-- CreateIndex
CREATE INDEX "ScimGroupMember_userId_idx" ON "ScimGroupMember"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "ScimGroupMember_groupId_userId_key" ON "ScimGroupMember"("groupId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "TotpRecoveryCode_hash_key" ON "TotpRecoveryCode"("hash");

-- CreateIndex
CREATE INDEX "TotpRecoveryCode_userId_idx" ON "TotpRecoveryCode"("userId");

-- CreateIndex
CREATE INDEX "DataExport_requestedById_createdAt_idx" ON "DataExport"("requestedById", "createdAt");

-- CreateIndex
CREATE INDEX "DataExport_orgId_createdAt_idx" ON "DataExport"("orgId", "createdAt");

-- CreateIndex
CREATE INDEX "DataExport_status_expiresAt_idx" ON "DataExport"("status", "expiresAt");

-- CreateIndex
CREATE INDEX "DeletionRequest_status_scheduledFor_idx" ON "DeletionRequest"("status", "scheduledFor");

-- CreateIndex
CREATE INDEX "DeletionRequest_userId_idx" ON "DeletionRequest"("userId");

-- CreateIndex
CREATE INDEX "DeletionRequest_orgId_idx" ON "DeletionRequest"("orgId");

-- CreateIndex
CREATE UNIQUE INDEX "PolicyPack_orgId_slug_key" ON "PolicyPack"("orgId", "slug");

-- CreateIndex
CREATE INDEX "Artifact_createdAt_idx" ON "Artifact"("createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_orgId_action_createdAt_idx" ON "AuditLog"("orgId", "action", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuditLog_chain_seq_key" ON "AuditLog"("chain", "seq");

-- CreateIndex
CREATE INDEX "ChatMessage_createdAt_idx" ON "ChatMessage"("createdAt");

-- CreateIndex
CREATE INDEX "Session_endedAt_idx" ON "Session"("endedAt");

-- AddForeignKey
ALTER TABLE "SsoConnection" ADD CONSTRAINT "SsoConnection_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoIdentity" ADD CONSTRAINT "SsoIdentity_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "SsoConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SsoIdentity" ADD CONSTRAINT "SsoIdentity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgDomain" ADD CONSTRAINT "OrgDomain_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimToken" ADD CONSTRAINT "ScimToken_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimIdentity" ADD CONSTRAINT "ScimIdentity_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimIdentity" ADD CONSTRAINT "ScimIdentity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimGroup" ADD CONSTRAINT "ScimGroup_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimGroupMember" ADD CONSTRAINT "ScimGroupMember_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "ScimGroup"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimGroupMember" ADD CONSTRAINT "ScimGroupMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TotpRecoveryCode" ADD CONSTRAINT "TotpRecoveryCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DataExport" ADD CONSTRAINT "DataExport_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DataExport" ADD CONSTRAINT "DataExport_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeletionRequest" ADD CONSTRAINT "DeletionRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DeletionRequest" ADD CONSTRAINT "DeletionRequest_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyPack" ADD CONSTRAINT "PolicyPack_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------------------------
-- Phase 10: immutable audit log (spec §8.20). Hand-written (not managed by Prisma).
-- Rows may only be changed by
--   * FK actions fired by another trigger (pg_trigger_depth() > 1): org deletion cascade,
--     user deletion SET NULL of "actorId";
--   * a transaction that ran  SELECT set_config('loose.audit_maintenance', 'on', true)
--     (retention purge, see phase10-design.md §2.2);
--   * direct UPDATEs that only redact personal data ("actorId" / "ip" set to NULL).
-- TRUNCATE (test database reset) does not fire row triggers.
CREATE OR REPLACE FUNCTION loose_audit_log_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
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
  IF NEW."id" IS DISTINCT FROM OLD."id"
     OR NEW."orgId" IS DISTINCT FROM OLD."orgId"
     OR NEW."action" IS DISTINCT FROM OLD."action"
     OR NEW."target" IS DISTINCT FROM OLD."target"
     OR NEW."meta" IS DISTINCT FROM OLD."meta"
     OR NEW."createdAt" IS DISTINCT FROM OLD."createdAt"
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

CREATE TRIGGER "AuditLog_immutable"
  BEFORE UPDATE OR DELETE ON "AuditLog"
  FOR EACH ROW EXECUTE FUNCTION loose_audit_log_guard();
