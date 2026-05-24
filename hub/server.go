package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// ingestServer implements the IngestService gRPC interface.
// It is the hub's entry point for everything the node sends.
type ingestServer struct {
	pb.UnimplementedIngestServiceServer
	log *slog.Logger
}

// newIngestServer builds an ingest server with the given logger.
func newIngestServer(log *slog.Logger) *ingestServer {
	return &ingestServer{log: log}
}

// SendProfile receives the environment snapshot sent at node startup.
func (s *ingestServer) SendProfile(
	ctx context.Context, p *pb.SystemProfile,
) (*pb.Ack, error) {
	os := p.GetOs()
	s.log.Info("system profile received",
		"node_id", p.GetNodeId(),
		"hostname", os.GetHostname(),
		"distribution", os.GetDistribution(),
		"version", os.GetVersion(),
		"services", len(p.GetServices()),
		"packages", len(p.GetPackages()),
		"failed_units", len(p.GetFailedUnits()),
	)
	return s.ack("profile stored"), nil
}

// SendTelemetry receives an anomaly event detected by the node at runtime.
func (s *ingestServer) SendTelemetry(
	ctx context.Context, e *pb.TelemetryEvent,
) (*pb.Ack, error) {
	s.log.Info("telemetry event received",
		"event_id", e.GetEventId(),
		"source", e.GetSource().String(),
		"severity", e.GetSeverity().String(),
	)
	return s.ack("telemetry stored"), nil
}

// ReportExecution receives the outcome of a remediation the node ran.
func (s *ingestServer) ReportExecution(
	ctx context.Context, r *pb.ExecutionResult,
) (*pb.Ack, error) {
	s.log.Info("execution result received",
		"plan_id", r.GetPlanId(),
		"success", r.GetSuccess(),
	)
	return s.ack("execution result stored"), nil
}

// ack builds a positive acknowledgement with a fresh receipt ID.
func (s *ingestServer) ack(msg string) *pb.Ack {
	return &pb.Ack{
		Accepted:   true,
		ReceiptId:  uuid.NewString(),
		ReceivedAt: timestamppb.New(time.Now()),
		Message:    msg,
	}
}
