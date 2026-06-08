package main

import (
	"fmt"
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

// uuidToString renders a pgtype.UUID as its canonical string form.
// Returns an empty string if the UUID is not valid (null).
func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
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
