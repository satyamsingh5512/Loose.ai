-- AlterTable
ALTER TABLE "Artifact" ADD COLUMN     "bytes" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "contentType" TEXT NOT NULL DEFAULT 'application/octet-stream',
ADD COLUMN     "storageKey" TEXT NOT NULL DEFAULT '';

-- AlterTable
ALTER TABLE "ChatMessage" ADD COLUMN     "clientMessageId" TEXT;

-- AlterTable
ALTER TABLE "Project" ADD COLUMN     "previousTemplateId" TEXT,
ADD COLUMN     "smokeTestAt" TIMESTAMP(3),
ADD COLUMN     "smokeTestFailedStep" TEXT,
ADD COLUMN     "smokeTestStatus" TEXT,
ADD COLUMN     "templateBuildFinishedAt" TIMESTAMP(3),
ADD COLUMN     "templateBuildId" TEXT,
ADD COLUMN     "templateBuildStartedAt" TIMESTAMP(3),
ADD COLUMN     "templateErrorDetail" JSONB,
ADD COLUMN     "templateSpecHash" TEXT;

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "budgetUsd" DECIMAL(12,4),
ADD COLUMN     "idleSince" TIMESTAMP(3),
ADD COLUMN     "lastEventSeq" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "runnerPid" INTEGER,
ADD COLUMN     "wipRef" TEXT;

-- AlterTable
ALTER TABLE "ToolApproval" ADD COLUMN     "decidedAt" TIMESTAMP(3),
ADD COLUMN     "expiresAt" TIMESTAMP(3),
ADD COLUMN     "gate" TEXT,
ADD COLUMN     "requiresAdmin" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "runnerRequestId" TEXT,
ADD COLUMN     "summary" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "ChatMessage_sessionId_clientMessageId_key" ON "ChatMessage"("sessionId", "clientMessageId");

-- CreateIndex
CREATE INDEX "Session_status_updatedAt_idx" ON "Session"("status", "updatedAt");

-- CreateIndex
CREATE INDEX "ToolApproval_status_expiresAt_idx" ON "ToolApproval"("status", "expiresAt");

