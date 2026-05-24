-- name: CreatePolicyDecision :one
-- Stores the policy engine's verdict for a plan.
INSERT INTO policy_decisions (
    plan_id, verdict
) VALUES (
    $1, $2
)
RETURNING *;

-- name: GetPolicyDecisionByPlan :one
-- Fetches the policy decision belonging to a given plan.
SELECT * FROM policy_decisions
WHERE plan_id = $1;

-- name: CreatePolicyFinding :one
-- Stores a single finding of a policy decision.
INSERT INTO policy_findings (
    decision_id, command_order, command_text, rule_id, action, description
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: ListFindingsByDecision :many
-- Lists the findings of a policy decision, in command order.
SELECT * FROM policy_findings
WHERE decision_id = $1
ORDER BY command_order ASC;