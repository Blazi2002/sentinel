package main

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/sentinel/sentinel/policy"
)

// uuidToPg converts a UUID string into the pgtype.UUID the database
// layer expects. An unparseable string yields a null UUID.
func uuidToPg(s string) pgtype.UUID {
	var out pgtype.UUID
	parsed, err := uuid.Parse(s)
	if err != nil {
		return out // Valid stays false: stored as NULL.
	}
	out.Bytes = parsed
	out.Valid = true
	return out
}

// timeToPg converts a time.Time into a pgtype.Timestamptz.
func timeToPg(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// policyVerdictToDB maps the policy engine's Verdict to the string
// value expected by the policy_verdict enum in the database.
func policyVerdictToDB(v policy.Verdict) string {
	switch v {
	case policy.VerdictApproved:
		return "approved"
	case policy.VerdictNeedsReview:
		return "needs_review"
	case policy.VerdictBlocked:
		return "blocked"
	default:
		return "needs_review" // Safe default: unknown verdict gets human review.
	}
}
