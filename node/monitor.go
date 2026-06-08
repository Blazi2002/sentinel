package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// NodeState is the current state of the node's state machine.
type NodeState string

const (
	StateIdle      NodeState = "idle"      // watching, nothing wrong
	StateCapturing NodeState = "capturing" // anomaly found, building event
	StateActuating NodeState = "actuating" // executing a remediation plan
)

// monitorInterval is how often the node checks system health.
const monitorInterval = 15 * time.Second

// Monitor is the node's live monitoring loop and state machine.
type Monitor struct {
	nodeID   string
	hub      *HubClient
	log      *slog.Logger
	state    NodeState
	executor *Executor
}

// NewMonitor builds a monitor ready to run.
func NewMonitor(nodeID string, hub *HubClient, executor *Executor, log *slog.Logger) *Monitor {
	return &Monitor{
		nodeID:   nodeID,
		hub:      hub,
		log:      log,
		state:    StateIdle,
		executor: executor,
	}
}

// Run starts the monitoring loop. It blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	m.log.Info("monitor started", "interval", monitorInterval.String())

	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	// Run one check immediately, then one on every tick.
	m.checkOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			m.log.Info("monitor stopping", "reason", ctx.Err())
			return
		case <-ticker.C:
			m.checkOnce(ctx)
		}
	}
}

// checkOnce runs a single cycle: detect-and-report anomalies, then
// pull-and-execute any approved plans.
func (m *Monitor) checkOnce(ctx context.Context) {
	// Part 1: detect anomalies and report them.
	anomalies := DetectAnomalies()
	if len(anomalies) > 0 {
		m.setState(StateCapturing)
		m.log.Warn("anomalies detected", "count", len(anomalies))
		for _, a := range anomalies {
			event := m.toTelemetryEvent(a)
			m.sendEvent(ctx, event, a.Summary)
		}
		m.setState(StateIdle)
	}

	// Part 2: fetch and execute any approved plans.
	m.executeApprovedPlans(ctx)
}

// executeApprovedPlans pulls approved plans from the hub and runs them.
func (m *Monitor) executeApprovedPlans(ctx context.Context) {
	resp, err := m.hub.GetApprovedPlans(ctx, m.nodeID)
	if err != nil {
		m.log.Error("failed to fetch approved plans", "error", err)
		return
	}
	plans := resp.GetPlans()
	if len(plans) == 0 {
		return
	}

	m.setState(StateActuating)
	m.log.Info("approved plans to execute", "count", len(plans))

	for _, plan := range plans {
		m.runPlan(ctx, plan)
	}

	m.setState(StateIdle)
}

// runPlan executes one approved plan and reports the outcome to the hub.
func (m *Monitor) runPlan(ctx context.Context, plan *pb.ApprovedPlan) {
	m.log.Info("executing approved plan",
		"incident_id", plan.GetIncidentId(),
		"commands", len(plan.GetCommands()),
	)

	// Convert wire commands into executor input.
	var planned []PlannedCommand
	for _, c := range plan.GetCommands() {
		planned = append(planned, PlannedCommand{
			Order:   c.GetOrder(),
			Command: c.GetCommand(),
			Action:  c.GetPolicyAction(),
		})
	}

	// Execute (dry-run by default). The executor skips non-allow commands.
	outcomes := m.executor.ExecutePlan(ctx, planned)

	// The plan succeeds if no executed command failed.
	success := true
	var output string
	for _, o := range outcomes {
		if o.Skipped {
			output += "[skipped] " + o.Command + "\n"
			continue
		}
		if !o.Success {
			success = false
		}
		output += o.Command + " -> " + o.Output + "\n"
	}

	// Report the outcome back to the hub.
	result := &pb.ExecutionResult{
		IncidentId: plan.GetIncidentId(),
		PlanId:     plan.GetPlanId(),
		Success:    success,
		Output:     output,
		ExecutedAt: timestamppb.Now(),
	}
	if _, err := m.hub.ReportExecution(ctx, result); err != nil {
		m.log.Error("failed to report execution",
			"incident_id", plan.GetIncidentId(), "error", err)
		return
	}
	m.log.Info("execution reported",
		"incident_id", plan.GetIncidentId(), "success", success)
}

// sendEvent ships one telemetry event to the hub.
func (m *Monitor) sendEvent(ctx context.Context, event *pb.TelemetryEvent, summary string) {
	ack, err := m.hub.SendTelemetry(ctx, event)
	if err != nil {
		m.log.Error("failed to send telemetry", "summary", summary, "error", err)
		return
	}
	m.log.Info("telemetry sent",
		"summary", summary,
		"receipt_id", ack.GetReceiptId(),
	)
}

// toTelemetryEvent converts an internal Anomaly into a wire TelemetryEvent.
func (m *Monitor) toTelemetryEvent(a Anomaly) *pb.TelemetryEvent {
	return &pb.TelemetryEvent{
		EventId:    uuid.NewString(),
		ObservedAt: timestamppb.Now(),
		Host:       &pb.HostInfo{NodeId: m.nodeID},
		Source:     a.Source,
		Severity:   a.Severity,
		RawPayload: a.Summary,
		Metrics:    a.Metrics,
		Labels:     a.Labels,
	}
}

// setState transitions the state machine and logs the change.
func (m *Monitor) setState(s NodeState) {
	if m.state == s {
		return
	}
	m.log.Info("state transition", "from", string(m.state), "to", string(s))
	m.state = s
}
