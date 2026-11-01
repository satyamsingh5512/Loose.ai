-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "prCreatedAt" TIMESTAMP(3),
ADD COLUMN     "prMergedAt" TIMESTAMP(3),
ADD COLUMN     "prNumber" INTEGER,
ADD COLUMN     "prState" TEXT;

