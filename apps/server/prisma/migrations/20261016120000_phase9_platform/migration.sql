-- CreateEnum
CREATE TYPE "RunStatus" AS ENUM ('QUEUED', 'PROVISIONING', 'RUNNING', 'WAITING_APPROVAL', 'CREATING_PR', 'SUCCEEDED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "RunSource" AS ENUM ('API', 'CLI', 'GITHUB_ACTION', 'GITHUB_ISSUE', 'GITHUB_COMMENT', 'SLACK', 'LINEAR', 'JIRA', 'SCHEDULE');

-- CreateEnum
CREATE TYPE "TriggerKind" AS ENUM ('GITHUB_ISSUE_LABEL', 'GITHUB_PR_COMMENT', 'SLACK_COMMAND', 'LINEAR', 'JIRA', 'SCHEDULE');

-- CreateEnum
CREATE TYPE "ShareRole" AS ENUM ('VIEWER', 'CO_EDITOR');

-- CreateEnum
CREATE TYPE "WebhookDeliveryStatus" AS ENUM ('PENDING', 'SUCCEEDED', 'FAILED');

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "baseBranch" TEXT,
ADD COLUMN     "controlTakenAt" TIMESTAMP(3),
ADD COLUMN     "controllerId" TEXT,
ADD COLUMN     "forkedFromCheckpointId" TEXT;

-- AlterTable
ALTER TABLE "Webhook" ADD COLUMN     "createdById" TEXT,
ADD COLUMN     "disabledAt" TIMESTAMP(3),
ADD COLUMN     "failureCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lastDeliveryAt" TIMESTAMP(3),
ADD COLUMN     "lastStatus" TEXT,
ADD COLUMN     "name" TEXT NOT NULL DEFAULT '';

-- CreateTable
CREATE TABLE "WebhookDelivery" (
    "id" TEXT NOT NULL,
    "webhookId" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "WebhookDeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3),
    "responseStatus" INTEGER,
    "responseSnippet" TEXT,
    "error" TEXT,
    "durationMs" INTEGER,
    "deliveredAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WebhookDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Run" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT,
    "apiTokenId" TEXT,
    "triggerId" TEXT,
    "source" "RunSource" NOT NULL DEFAULT 'API',
    "status" "RunStatus" NOT NULL DEFAULT 'QUEUED',
    "prompt" TEXT NOT NULL,
    "options" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "externalRef" JSONB,
    "summary" TEXT,
    "filesChanged" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "prUrl" TEXT,
    "prNumber" INTEGER,
    "errorCode" TEXT,
    "costUsd" DECIMAL(12,4) NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Run_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Trigger" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "kind" "TriggerKind" NOT NULL,
    "name" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "config" JSONB NOT NULL DEFAULT '{}',
    "promptTemplate" TEXT NOT NULL DEFAULT '',
    "runAsUserId" TEXT NOT NULL,
    "createPr" BOOLEAN NOT NULL DEFAULT true,
    "mode" "Mode" NOT NULL DEFAULT 'PRO',
    "model" TEXT,
    "nextRunAt" TIMESTAMP(3),
    "lastFiredAt" TIMESTAMP(3),
    "lastRunId" TEXT,
    "lastError" TEXT,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Trigger_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TriggerFire" (
    "id" TEXT NOT NULL,
    "triggerId" TEXT NOT NULL,
    "dedupeKey" TEXT NOT NULL,
    "runId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TriggerFire_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SessionCollaborator" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "ShareRole" NOT NULL,
    "invitedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SessionCollaborator_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "WebhookDelivery_webhookId_createdAt_idx" ON "WebhookDelivery"("webhookId", "createdAt");

-- CreateIndex
CREATE INDEX "WebhookDelivery_status_nextAttemptAt_idx" ON "WebhookDelivery"("status", "nextAttemptAt");

-- CreateIndex
CREATE UNIQUE INDEX "WebhookDelivery_webhookId_eventId_key" ON "WebhookDelivery"("webhookId", "eventId");

-- CreateIndex
CREATE UNIQUE INDEX "Run_sessionId_key" ON "Run"("sessionId");

-- CreateIndex
CREATE INDEX "Run_orgId_createdAt_idx" ON "Run"("orgId", "createdAt");

-- CreateIndex
CREATE INDEX "Run_userId_createdAt_idx" ON "Run"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "Run_status_updatedAt_idx" ON "Run"("status", "updatedAt");

-- CreateIndex
CREATE INDEX "Run_triggerId_createdAt_idx" ON "Run"("triggerId", "createdAt");

-- CreateIndex
CREATE INDEX "Trigger_orgId_idx" ON "Trigger"("orgId");

-- CreateIndex
CREATE INDEX "Trigger_projectId_idx" ON "Trigger"("projectId");

-- CreateIndex
CREATE INDEX "Trigger_kind_enabled_idx" ON "Trigger"("kind", "enabled");

-- CreateIndex
CREATE INDEX "Trigger_enabled_nextRunAt_idx" ON "Trigger"("enabled", "nextRunAt");

-- CreateIndex
CREATE UNIQUE INDEX "TriggerFire_triggerId_dedupeKey_key" ON "TriggerFire"("triggerId", "dedupeKey");

-- CreateIndex
CREATE INDEX "SessionCollaborator_userId_idx" ON "SessionCollaborator"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "SessionCollaborator_sessionId_userId_key" ON "SessionCollaborator"("sessionId", "userId");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_controllerId_fkey" FOREIGN KEY ("controllerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Webhook" ADD CONSTRAINT "Webhook_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WebhookDelivery" ADD CONSTRAINT "WebhookDelivery_webhookId_fkey" FOREIGN KEY ("webhookId") REFERENCES "Webhook"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Run" ADD CONSTRAINT "Run_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Run" ADD CONSTRAINT "Run_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Run" ADD CONSTRAINT "Run_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Run" ADD CONSTRAINT "Run_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Run" ADD CONSTRAINT "Run_apiTokenId_fkey" FOREIGN KEY ("apiTokenId") REFERENCES "ApiToken"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Run" ADD CONSTRAINT "Run_triggerId_fkey" FOREIGN KEY ("triggerId") REFERENCES "Trigger"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Trigger" ADD CONSTRAINT "Trigger_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Trigger" ADD CONSTRAINT "Trigger_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Trigger" ADD CONSTRAINT "Trigger_runAsUserId_fkey" FOREIGN KEY ("runAsUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Trigger" ADD CONSTRAINT "Trigger_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TriggerFire" ADD CONSTRAINT "TriggerFire_triggerId_fkey" FOREIGN KEY ("triggerId") REFERENCES "Trigger"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionCollaborator" ADD CONSTRAINT "SessionCollaborator_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionCollaborator" ADD CONSTRAINT "SessionCollaborator_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SessionCollaborator" ADD CONSTRAINT "SessionCollaborator_invitedById_fkey" FOREIGN KEY ("invitedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
