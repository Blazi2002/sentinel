package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinel/sentinel/hub/db"
)

// Store is the hub's persistence layer. It wraps the generated db
// queries and exposes higher-level operations that span multiple
// tables, always inside a transaction so a save is all-or-nothing.
type Store struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewStore connects to PostgreSQL and returns a ready Store.
// connString is a postgres:// URL.
func NewStore(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("database not reachable: %w", err)
	}
	return &Store{
		pool:    pool,
		queries: db.New(pool),
	}, nil
}

// Close releases the database connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// IncidentInput bundles everything needed to persist one incident:
// the anomaly, the plan, its commands, and the policy decision.
type IncidentInput struct {
	EventID    pgtype.UUID
	NodeID     pgtype.UUID
	Severity   string
	Source     string
	Summary    string
	DetectedAt pgtype.Timestamptz

	RootCause   string
	RiskLevel   string
	Confidence  float64
	GeneratedAt pgtype.Timestamptz
	Commands    []CommandInput

	Verdict  string
	Findings []FindingInput
}

// CommandInput is one remediation command to persist.
type CommandInput struct {
	Order       int32
	Text        string
	Explanation string
	Rollback    string
}

// FindingInput is one policy finding to persist.
type FindingInput struct {
	Order       int32
	CommandText string
	RuleID      string
	Action      string
	Description string
}

// SaveIncident persists a full incident — anomaly, plan, commands,
// decision and findings — inside a single transaction. If any step
// fails, nothing is written.
func (s *Store) SaveIncident(ctx context.Context, in IncidentInput) (pgtype.UUID, error) {
	var noID pgtype.UUID

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return noID, fmt.Errorf("starting transaction: %w", err)
	}
	// If we return before Commit, rollback undoes everything.
	defer tx.Rollback(ctx)

	q := s.queries.WithTx(tx)

	// 1. The incident.
	incident, err := q.CreateIncident(ctx, db.CreateIncidentParams{
		EventID:    in.EventID,
		NodeID:     in.NodeID,
		Severity:   in.Severity,
		Source:     in.Source,
		Summary:    in.Summary,
		DetectedAt: in.DetectedAt,
	})
	if err != nil {
		return noID, fmt.Errorf("saving incident: %w", err)
	}

	// 2. The plan.
	plan, err := q.CreatePlan(ctx, db.CreatePlanParams{
		IncidentID:  incident.ID,
		RootCause:   in.RootCause,
		RiskLevel:   in.RiskLevel,
		Confidence:  in.Confidence,
		GeneratedAt: in.GeneratedAt,
	})
	if err != nil {
		return noID, fmt.Errorf("saving plan: %w", err)
	}

	// 3. The commands.
	for _, c := range in.Commands {
		_, err := q.CreateCommand(ctx, db.CreateCommandParams{
			PlanID:          plan.ID,
			CommandOrder:    c.Order,
			CommandText:     c.Text,
			Explanation:     c.Explanation,
			RollbackCommand: c.Rollback,
		})
		if err != nil {
			return noID, fmt.Errorf("saving command %d: %w", c.Order, err)
		}
	}

	// 4. The policy decision.
	decision, err := q.CreatePolicyDecision(ctx, db.CreatePolicyDecisionParams{
		PlanID:  plan.ID,
		Verdict: db.PolicyVerdict(in.Verdict),
	})
	if err != nil {
		return noID, fmt.Errorf("saving policy decision: %w", err)
	}

	// 5. The policy findings.
	for _, f := range in.Findings {
		_, err := q.CreatePolicyFinding(ctx, db.CreatePolicyFindingParams{
			DecisionID:   decision.ID,
			CommandOrder: f.Order,
			CommandText:  f.CommandText,
			RuleID:       f.RuleID,
			Action:       f.Action,
			Description:  f.Description,
		})
		if err != nil {
			return noID, fmt.Errorf("saving finding %d: %w", f.Order, err)
		}
	}

	// Everything succeeded — make it permanent.
	if err := tx.Commit(ctx); err != nil {
		return noID, fmt.Errorf("committing transaction: %w", err)
	}
	return incident.ID, nil
}

// ListIncidents returns all incidents, newest first.
func (s *Store) ListIncidents(ctx context.Context) ([]db.Incident, error) {
	return s.queries.ListIncidents(ctx)
}

// IncidentDetail is a fully-assembled incident for the dashboard:
// the incident plus its plan, commands, policy decision and findings.
type IncidentDetail struct {
	Incident db.Incident
	Plan     db.Plan
	Commands []db.Command
	Decision db.PolicyDecision
	Findings []db.PolicyFinding
}

// GetIncidentDetail assembles the full picture of one incident by ID.
func (s *Store) GetIncidentDetail(
	ctx context.Context, id pgtype.UUID,
) (*IncidentDetail, error) {
	incident, err := s.queries.GetIncident(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("loading incident: %w", err)
	}

	plan, err := s.queries.GetPlanByIncident(ctx, incident.ID)
	if err != nil {
		return nil, fmt.Errorf("loading plan: %w", err)
	}

	commands, err := s.queries.ListCommandsByPlan(ctx, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("loading commands: %w", err)
	}

	decision, err := s.queries.GetPolicyDecisionByPlan(ctx, plan.ID)
	if err != nil {
		return nil, fmt.Errorf("loading policy decision: %w", err)
	}

	findings, err := s.queries.ListFindingsByDecision(ctx, decision.ID)
	if err != nil {
		return nil, fmt.Errorf("loading findings: %w", err)
	}

	return &IncidentDetail{
		Incident: incident,
		Plan:     plan,
		Commands: commands,
		Decision: decision,
		Findings: findings,
	}, nil
}

// DecideIncident records an operator's approve/reject decision.
func (s *Store) DecideIncident(
	ctx context.Context, id pgtype.UUID, status, decidedBy, note string,
) (db.Incident, error) {
	return s.queries.UpdateIncidentDecision(ctx, db.UpdateIncidentDecisionParams{
		ID:           id,
		Status:       db.IncidentStatus(status),
		DecidedBy:    &decidedBy,
		DecisionNote: &note,
	})
}
