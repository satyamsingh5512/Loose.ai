-- AlterTable
ALTER TABLE "ChatMessage" ADD COLUMN     "rewoundAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Checkpoint" ADD COLUMN     "agentSessionId" TEXT,
ADD COLUMN     "conversationAnchor" TEXT,
ADD COLUMN     "hasCode" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "rewoundAt" TIMESTAMP(3),
ADD COLUMN     "turn" INTEGER NOT NULL DEFAULT 1;

-- AlterTable
ALTER TABLE "McpServer" ADD COLUMN     "catalogId" TEXT,
ADD COLUMN     "lastTools" JSONB;

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "memory" TEXT,
ADD COLUMN     "memoryUpdatedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Project" ADD COLUMN     "extensionOverrides" JSONB NOT NULL DEFAULT '{}',
ADD COLUMN     "planMode" TEXT NOT NULL DEFAULT 'AUTO',
ADD COLUMN     "repoMemory" TEXT NOT NULL DEFAULT 'prefer_loose';

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "notes" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "resumeSessionAt" TEXT;

-- AlterTable
ALTER TABLE "Skill" ADD COLUMN     "files" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "quickAction" TEXT,
ALTER COLUMN "bundleUrl" SET DEFAULT '';

-- AlterTable
ALTER TABLE "ToolApproval" ADD COLUMN     "kind" TEXT NOT NULL DEFAULT 'tool',
ADD COLUMN     "messageId" TEXT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "memory" TEXT,
ADD COLUMN     "memoryUpdatedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "SkillVersion" (
    "id" TEXT NOT NULL,
    "skillId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "description" TEXT NOT NULL,
    "files" JSONB NOT NULL,
    "bytes" INTEGER NOT NULL DEFAULT 0,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SkillVersion_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SkillVersion_skillId_version_key" ON "SkillVersion"("skillId", "version");

-- CreateIndex
CREATE INDEX "Skill_orgId_idx" ON "Skill"("orgId");

-- AddForeignKey
ALTER TABLE "SkillVersion" ADD CONSTRAINT "SkillVersion_skillId_fkey" FOREIGN KEY ("skillId") REFERENCES "Skill"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SkillVersion" ADD CONSTRAINT "SkillVersion_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

