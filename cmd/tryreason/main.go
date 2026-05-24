// Command tryreason is a manual test: it feeds a synthetic anomaly to
// the reasoning engine and prints the remediation plan the LLM produces.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
	"github.com/sentinel/sentinel/reasoning"
)

const model = "qwen2.5-coder:7b"

func main() {
	fmt.Println("Reasoning engine — manual test")
	fmt.Println("------------------------------------------------------------")

	reasoner := reasoning.NewReasoner(model)

	// Make sure Ollama is reachable before doing anything.
	ctx := context.Background()
	if err := reasoner.Health(ctx); err != nil {
		fmt.Printf("ERROR: Ollama is not reachable: %v\n", err)
		fmt.Println("Is `ollama serve` running?")
		os.Exit(1)
	}
	fmt.Println("Ollama reachable. Model:", model)

	// Build a synthetic anomaly: a filesystem almost full.
	event := &pb.TelemetryEvent{
		EventId:    uuid.NewString(),
		ObservedAt: timestamppb.Now(),
		Source:     pb.Source_SOURCE_METRICS,
		Severity:   pb.Severity_SEVERITY_ERROR,
		RawPayload: "filesystem /var at 96.4% full",
		Metrics: []*pb.MetricSample{
			{Name: "disk.used.percent", Value: 96.4, Unit: "percent"},
		},
		Labels: map[string]string{"mount_point": "/var"},
	}

	fmt.Println("\nAnomaly to diagnose:")
	fmt.Println(" ", event.GetRawPayload())
	fmt.Println("\nAsking the LLM (this may take 10-30 seconds)...")

	// Run the reasoning step.
	start := time.Now()
	analyzeCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	plan, err := reasoner.Analyze(analyzeCtx, event)
	if err != nil {
		fmt.Printf("ERROR: reasoning failed: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)

	// Print the remediation plan the model produced.
	printPlan(plan, elapsed)
}

// printPlan renders a RemediationPlan in human-readable form.
func printPlan(plan *pb.RemediationPlan, elapsed time.Duration) {
	line := "------------------------------------------------------------"
	fmt.Println("\n" + line)
	fmt.Println("REMEDIATION PLAN")
	fmt.Println(line)
	fmt.Printf("Plan ID:     %s\n", plan.GetPlanId())
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
