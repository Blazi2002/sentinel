-- Reverts the initial schema. Tables are dropped in reverse dependency
-- order so foreign keys never block the drop.

DROP TABLE IF EXISTS policy_findings;
DROP TABLE IF EXISTS policy_decisions;
DROP TABLE IF EXISTS commands;
DROP TABLE IF EXISTS plans;
DROP TABLE IF EXISTS incidents;

DROP TYPE IF EXISTS policy_verdict;
DROP TYPE IF EXISTS incident_status;