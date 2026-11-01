-- P10-SEC-006: durable audit chain cutover marker.
-- Unchained ("legacy") audit rows are only acceptable if they predate this instant; verification
-- reports any later unchained row as a break.
CREATE TABLE "AuditChainCutover" (
  "id"        TEXT         NOT NULL DEFAULT 'singleton',
  "cutoverAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AuditChainCutover_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AuditChainCutover_singleton" CHECK ("id" = 'singleton')
);

INSERT INTO "AuditChainCutover" ("id", "cutoverAt") VALUES ('singleton', CURRENT_TIMESTAMP(3));
