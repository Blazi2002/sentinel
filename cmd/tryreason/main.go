// Command tryreason is a manual test: it feeds a synthetic anomaly to
// the reasoning engine, then runs the resulting plan through the
// policy engine and prints both the plan and the safety verdict.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
	"github.com/sentinel/sentinel/policy"
	"github.com/sentinel/sentinel/reasoning"
)

const model = "qwen2.5-coder:7b"

func main() {
	fmt.Println("Reasoning + Policy — manual test")
	fmt.Println("------------------------------------------------------------")

	reasoner := reasoning.NewReasoner(model)

	ctx := context.Background()
	if err := reasoner.Health(ctx); err != nil {
		fmt.Printf("ERROR: Ollama is not reachable: %v\n", err)
		fmt.Println("Is `ollama serve` running?")
		os.Exit(1)
	}
	fmt.Println("Ollama reachable. Model:", model)

	// Build a synthetic anomaly that pushes the LLM toward a
	// high-impact action the policy engine will catch.
	event := &pb.TelemetryEvent{
		EventId:    uuid.NewString(),
		ObservedAt: timestamppb.Now(),
		Source:     pb.Source_SOURCE_JOURNALD,
		Severity:   pb.Severity_SEVERITY_CRITICAL,
		RawPayload: "sshd reports a flood of failed login attempts from IP 203.0.113.66 — possible brute-force attack",
		Labels: map[string]string{
			"service":    "sshd",
			"source_ip":  "203.0.113.66",
			"event_type": "security",
		},
	}

	fmt.Println("\nAnomaly to diagnose:")
	fmt.Println(" ", event.GetRawPayload())
	fmt.Println("\nAsking the LLM (this may take 10-30 seconds)...")

	start := time.Now()
	analyzeCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	plan, err := reasoner.Analyze(analyzeCtx, event)
	if err != nil {
		fmt.Printf("ERROR: reasoning failed: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	printPlan(plan, elapsed)

	// --- Anello successivo: il piano passa dal policy engine ---
	fmt.Println("\nRunning the plan through the policy engine...")
	engine := policy.NewEngine()

	// Extract the raw command strings from the plan, in order.
	var commands []string
	for _, c := range plan.GetCommands() {
		commands = append(commands, c.GetCommand())
	}

	decision := engine.Evaluate(commands)
	printDecision(decision)
}

// printPlan renders a RemediationPlan in human-readable form.
func printPlan(plan *pb.RemediationPlan, elapsed time.Duration) {
	line := "------------------------------------------------------------"
	fmt.Println("\n" + line)
	fmt.Println("REMEDIATION PLAN (from LLM)")
	fmt.Println(line)
	fmt.Printf("Risk level:  %s\n", plan.GetRiskLevel().String())
	fmt.Printf("Confidence:  %.2f\n", plan.GetConfidence())
	fmt.Println(line)
	fmt.Printf("Root cause:\n  %s\n", plan.GetRootCause())
	fmt.Println(line)
	fmt.Printf("Commands (%d):\n", len(plan.GetCommands()))
	for _, c := range plan.GetCommands() {
		fmt.Printf("\n  [%d] %s\n", c.GetOrder(), c.GetCommand())
		fmt.Printf("      why: %s\n", c.GetExplanation())
		if rb := c.GetRollbackCommand(); rb != "" {
			fmt.Printf("      rollback: %s\n", rb)
		}
	}
	fmt.Println("\n" + line)
	fmt.Printf("Generated in %s\n", elapsed.Round(time.Millisecond))
}

// printDecision renders the policy engine's verdict.
func printDecision(d policy.Decision) {
	line := "------------------------------------------------------------"
	fmt.Println("\n" + line)
	fmt.Println("POLICY DECISION")
	fmt.Println(line)
	fmt.Printf("Overall verdict: %s\n", d.Verdict)
	fmt.Println(line)
	for _, f := range d.Findings {
		fmt.Printf("\n  [%d] %s\n", f.CommandOrder, f.CommandText)
		fmt.Printf("      action: %s\n", f.Action)
		if f.RuleID != "" {
			fmt.Printf("      rule:   %s\n", f.RuleID)
		}
		fmt.Printf("      reason: %s\n", f.Description)
	}
	fmt.Println("\n" + line)
	fmt.Println(d.Summary())
}
