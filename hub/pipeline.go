package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
	"github.com/sentinel/sentinel/policy"
	"github.com/sentinel/sentinel/reasoning"
)

// Pipeline ties together the three stages that turn an incoming
// telemetry event into a stored incident: reasoning, policy, persistence.
type Pipeline struct {
	reasoner *reasoning.Reasoner
	policy   *policy.Engine
	store    *Store
	log      *slog.Logger
}

// NewPipeline builds a pipeline from its three dependencies.
func NewPipeline(
	reasoner *reasoning.Reasoner,
	policyEngine *policy.Engine,
	store *Store,
	log *slog.Logger,
) *Pipeline {
	return &Pipeline{
		reasoner: reasoner,
		policy:   policyEngine,
		store:    store,
		log:      log,
	}
}

// Process runs one telemetry event through the full chain and stores
// the resulting incident. It returns the new incident's ID.
func (p *Pipeline) Process(
	ctx context.Context, event *pb.TelemetryEvent,
) (pgtype.UUID, error) {
	var noID pgtype.UUID

	// Stage 1 — Reasoning: the LLM diagnoses and proposes a plan.
	p.log.Info("pipeline: reasoning", "event_id", event.GetEventId())
	plan, err := p.reasoner.Analyze(ctx, event)
	if err != nil {
		return noID, fmt.Errorf("reasoning stage: %w", err)
	}

	// Stage 2 — Policy: the deterministic engine validates the plan.
	p.log.Info("pipeline: policy validation", "event_id", event.GetEventId())
	var commandStrings []string
	for _, c := range plan.GetCommands() {
		commandStrings = append(commandStrings, c.GetCommand())
	}
	decision := p.policy.Evaluate(commandStrings)

	// Stage 3 — Persistence: store the whole incident atomically.
	p.log.Info("pipeline: persisting incident", "event_id", event.GetEventId())
	input := p.buildIncidentInput(event, plan, decision)
	incidentID, err := p.store.SaveIncident(ctx, input)
	if err != nil {
		return noID, fmt.Errorf("persistence stage: %w", err)
	}

	p.log.Info("pipeline: incident stored",
		"event_id", event.GetEventId(),
		"verdict", decision.Verdict.String(),
	)
	return incidentID, nil
}

// buildIncidentInput assembles the data from all three stages into the
// IncidentInput struct the store expects.
func (p *Pipeline) buildIncidentInput(
	event *pb.TelemetryEvent,
	plan *pb.RemediationPlan,
	decision policy.Decision,
) IncidentInput {
	// Map the plan's commands.
	var commands []CommandInput
	for _, c := range plan.GetCommands() {
		commands = append(commands, CommandInput{
			Order:       c.GetOrder(),
			Text:        c.GetCommand(),
			Explanation: c.GetExplanation(),
			Rollback:    c.GetRollbackCommand(),
		})
	}

	// Map the policy findings.
	var findings []FindingInput
	for _, f := range decision.Findings {
		findings = append(findings, FindingInput{
			Order:       int32(f.CommandOrder),
			CommandText: f.CommandText,
			RuleID:      f.RuleID,
			Action:      f.Action.String(),
			Description: f.Description,
		})
	}

	return IncidentInput{
		EventID:    uuidToPg(event.GetEventId()),
		NodeID:     uuidToPg(event.GetHost().GetNodeId()),
		Severity:   event.GetSeverity().String(),
		Source:     event.GetSource().String(),
		Summary:    event.GetRawPayload(),
		DetectedAt: timeToPg(event.GetObservedAt().AsTime()),

		RootCause:   plan.GetRootCause(),
		RiskLevel:   plan.GetRiskLevel().String(),
		Confidence:  plan.GetConfidence(),
		GeneratedAt: timeToPg(plan.GetGeneratedAt().AsTime()),
		Commands:    commands,

		Verdict:  policyVerdictToDB(decision.Verdict),
		Findings: findings,
	}
}
