-- AlterTable
ALTER TABLE "Hook" ADD COLUMN     "failMode" TEXT NOT NULL DEFAULT 'closed',
ADD COLUMN     "lastDecision" TEXT,
ADD COLUMN     "lastError" TEXT,
ADD COLUMN     "lastRunAt" TIMESTAMP(3),
ADD COLUMN     "name" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "recipe" TEXT,
ADD COLUMN     "secretEnc" BYTEA,
ADD COLUMN     "timeoutSec" INTEGER NOT NULL DEFAULT 10;

-- AlterTable
ALTER TABLE "Plugin" ADD COLUMN     "createdById" TEXT,
ALTER COLUMN "bundleUrl" SET DEFAULT '';

-- AlterTable
ALTER TABLE "Project" ADD COLUMN     "autoCompactPercent" INTEGER NOT NULL DEFAULT 80,
ADD COLUMN     "screenshotViewports" TEXT[] DEFAULT ARRAY['desktop']::TEXT[];

-- AlterTable
ALTER TABLE "Subagent" ADD COLUMN     "enabled" BOOLEAN NOT NULL DEFAULT true;

-- CreateTable
CREATE TABLE "PluginVersion" (
    "id" TEXT NOT NULL,
    "pluginId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "manifest" JSONB NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PluginVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PluginInstall" (
    "id" TEXT NOT NULL,
    "pluginId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "credentialsEnc" BYTEA,
    "credentialMeta" JSONB NOT NULL DEFAULT '{}',
    "resources" JSONB NOT NULL DEFAULT '{}',
    "installedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PluginInstall_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PluginVersion_pluginId_version_key" ON "PluginVersion"("pluginId", "version");

-- CreateIndex
CREATE INDEX "PluginInstall_projectId_idx" ON "PluginInstall"("projectId");

-- CreateIndex
CREATE UNIQUE INDEX "PluginInstall_pluginId_projectId_key" ON "PluginInstall"("pluginId", "projectId");

-- CreateIndex
CREATE INDEX "Hook_orgId_event_enabled_idx" ON "Hook"("orgId", "event", "enabled");

-- CreateIndex
CREATE INDEX "Hook_projectId_event_enabled_idx" ON "Hook"("projectId", "event", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "Plugin_orgId_name_key" ON "Plugin"("orgId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "Subagent_scope_orgId_projectId_userId_name_key" ON "Subagent"("scope", "orgId", "projectId", "userId", "name");

-- CreateIndex
CREATE INDEX "UsageEvent_orgId_subagent_idx" ON "UsageEvent"("orgId", "subagent");

-- AddForeignKey
ALTER TABLE "Plugin" ADD CONSTRAINT "Plugin_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PluginVersion" ADD CONSTRAINT "PluginVersion_pluginId_fkey" FOREIGN KEY ("pluginId") REFERENCES "Plugin"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PluginVersion" ADD CONSTRAINT "PluginVersion_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PluginInstall" ADD CONSTRAINT "PluginInstall_pluginId_fkey" FOREIGN KEY ("pluginId") REFERENCES "Plugin"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PluginInstall" ADD CONSTRAINT "PluginInstall_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PluginInstall" ADD CONSTRAINT "PluginInstall_installedById_fkey" FOREIGN KEY ("installedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

