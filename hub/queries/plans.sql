-- name: CreatePlan :one
-- Stores the remediation plan generated for an incident.
INSERT INTO plans (
    incident_id, root_cause, risk_level, confidence, generated_at
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: GetPlanByIncident :one
-- Fetches the plan belonging to a given incident.
SELECT * FROM plans
WHERE incident_id = $1;

-- name: CreateCommand :one
-- Stores a single command of a plan.
INSERT INTO commands (
    plan_id, command_order, command_text, explanation, rollback_command
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING *;

-- name: ListCommandsByPlan :many
-- Lists the commands of a plan, in execution order.
SELECT * FROM commands
WHERE plan_id = $1
ORDER BY command_order ASC;