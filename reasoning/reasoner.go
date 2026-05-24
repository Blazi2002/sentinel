package reasoning

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// llmPlan mirrors the JSON structure the model is instructed to emit.
// It is an intermediate type: we decode the model's text into this,
// then convert it into a proper RemediationPlan protobuf message.
type llmPlan struct {
	RootCause  string       `json:"root_cause"`
	RiskLevel  string       `json:"risk_level"`
	Confidence float64      `json:"confidence"`
	Commands   []llmCommand `json:"commands"`
}

type llmCommand struct {
	Command         string `json:"command"`
	Explanation     string `json:"explanation"`
	RollbackCommand string `json:"rollback_command"`
}

// Reasoner turns telemetry events into remediation plans using an LLM.
type Reasoner struct {
	llm *OllamaClient
}

// NewReasoner builds a reasoner backed by the given model.
func NewReasoner(model string) *Reasoner {
	return &Reasoner{llm: NewOllamaClient(model)}
}

// Health verifies the underlying LLM engine is reachable.
func (r *Reasoner) Health(ctx context.Context) error {
	return r.llm.Health(ctx)
}

// Analyze sends one telemetry event to the LLM and returns a
// structured RemediationPlan.
func (r *Reasoner) Analyze(
	ctx context.Context, event *pb.TelemetryEvent,
) (*pb.RemediationPlan, error) {
	userPrompt := BuildUserPrompt(event)

	// forceJSON = true: the model is constrained to emit valid JSON.
	raw, err := r.llm.Generate(ctx, systemPrompt, userPrompt, true)
	if err != nil {
		return nil, fmt.Errorf("llm generation failed: %w", err)
	}

	var parsed llmPlan
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("model did not return valid JSON: %w", err)
	}

	return r.toRemediationPlan(event, parsed), nil
}

// toRemediationPlan converts the decoded LLM output into a protobuf
// RemediationPlan, ready to hand to the policy engine.
func (r *Reasoner) toRemediationPlan(
	event *pb.TelemetryEvent, p llmPlan,
) *pb.RemediationPlan {
	var commands []*pb.RemediationCommand
	for i, c := range p.Commands {
		commands = append(commands, &pb.RemediationCommand{
			Order:           int32(i + 1),
			ActionType:      pb.ActionType_ACTION_TYPE_SHELL,
			Command:         c.Command,
			Explanation:     c.Explanation,
			RollbackCommand: c.RollbackCommand,
		})
	}

	return &pb.RemediationPlan{
		PlanId:      uuid.NewString(),
		EventId:     event.GetEventId(),
		GeneratedAt: timestamppb.Now(),
		RootCause:   p.RootCause,
		RiskLevel:   parseRiskLevel(p.RiskLevel),
		Commands:    commands,
		Confidence:  clampConfidence(p.Confidence),
	}
}

// parseRiskLevel maps the model's risk word to the RiskLevel enum.
// An unrecognized value is treated as CRITICAL — the safe default:
// if the model's risk output is garbled, assume the worst.
func parseRiskLevel(s string) pb.RiskLevel {
	switch s {
	case "LOW":
		return pb.RiskLevel_RISK_LEVEL_LOW
	case "MEDIUM":
		return pb.RiskLevel_RISK_LEVEL_MEDIUM
	case "HIGH":
		return pb.RiskLevel_RISK_LEVEL_HIGH
	case "CRITICAL":
		return pb.RiskLevel_RISK_LEVEL_CRITICAL
	default:
		return pb.RiskLevel_RISK_LEVEL_CRITICAL
	}
}

// clampConfidence forces the confidence into the valid 0.0–1.0 range,
// in case the model emits something out of bounds.
func clampConfidence(c float64) float64 {
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}
