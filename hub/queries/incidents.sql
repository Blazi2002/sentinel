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

-- name: FilterIncidents :many
-- Lists incidents matching optional filters. An empty/zero filter
-- argument disables that filter. The time window is an optional
-- [from, to] range; either bound may be null. Newest first.
SELECT * FROM incidents
WHERE
    (sqlc.arg(severity)::text   = '' OR severity = sqlc.arg(severity)::text)
    AND (sqlc.arg(status)::text = '' OR status::text = sqlc.arg(status)::text)
    AND (sqlc.arg(source)::text = '' OR source = sqlc.arg(source)::text)
    AND (sqlc.narg(from_time)::timestamptz IS NULL
         OR detected_at >= sqlc.narg(from_time)::timestamptz)
    AND (sqlc.narg(to_time)::timestamptz IS NULL
         OR detected_at <= sqlc.narg(to_time)::timestamptz)
    AND (sqlc.arg(search)::text = ''
         OR summary ILIKE '%' || sqlc.arg(search)::text || '%')
ORDER BY detected_at DESC;