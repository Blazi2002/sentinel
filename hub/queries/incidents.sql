-- name: CreateIncident :one
-- Records a new incident detected by a node.
INSERT INTO incidents (
    event_id, node_id, severity, source, summary, detected_at
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: GetIncident :one
-- Fetches a single incident by its ID.
SELECT * FROM incidents
WHERE id = $1;

-- name: ListIncidents :many
-- Lists all incidents, newest first. Used by the dashboard.
SELECT * FROM incidents
ORDER BY detected_at DESC;

-- name: ListIncidentsByStatus :many
-- Lists incidents in a given lifecycle state, newest first.
SELECT * FROM incidents
WHERE status = $1
ORDER BY detected_at DESC;

-- name: UpdateIncidentDecision :one
-- Records an operator's approve/reject decision on an incident.
UPDATE incidents
SET status = $2,
    decided_by = $3,
    decided_at = now(),
    decision_note = $4
WHERE id = $1
RETURNING *;

-- name: UpdateIncidentStatus :one
-- Updates only the lifecycle status (e.g. to 'executed' or 'failed').
UPDATE incidents
SET status = $1
WHERE id = $2
RETURNING *;