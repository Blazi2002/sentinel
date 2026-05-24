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
	nodeID string
	hub    *HubClient
	log    *slog.Logger
	state  NodeState
}

// NewMonitor builds a monitor ready to run.
func NewMonitor(nodeID string, hub *HubClient, log *slog.Logger) *Monitor {
	return &Monitor{
		nodeID: nodeID,
		hub:    hub,
		log:    log,
		state:  StateIdle,
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

// checkOnce runs a single health check cycle.
func (m *Monitor) checkOnce(ctx context.Context) {
	anomalies := DetectAnomalies()
	if len(anomalies) == 0 {
		m.log.Debug("health check ok", "state", string(m.state))
		return
	}

	// Anomalies found — move to Capturing for the duration of handling.
	m.setState(StateCapturing)
	m.log.Warn("anomalies detected", "count", len(anomalies))

	for _, a := range anomalies {
		event := m.toTelemetryEvent(a)
		m.sendEvent(ctx, event, a.Summary)
	}

	m.setState(StateIdle)
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
