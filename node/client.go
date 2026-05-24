package main

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// HubClient wraps the gRPC connection from the node to the hub.
type HubClient struct {
	conn   *grpc.ClientConn
	ingest pb.IngestServiceClient
}

// NewHubClient dials the hub at the given address and returns a client.
// NOTE: this uses an insecure (plaintext) connection. mTLS will be
// added in a later step — for now we validate the transport itself.
func NewHubClient(address string) (*HubClient, error) {
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dialing hub at %s: %w", address, err)
	}
	return &HubClient{
		conn:   conn,
		ingest: pb.NewIngestServiceClient(conn),
	}, nil
}

// SendProfile sends the system profile to the hub and returns the Ack.
func (c *HubClient) SendProfile(
	ctx context.Context, profile *pb.SystemProfile,
) (*pb.Ack, error) {
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ack, err := c.ingest.SendProfile(sendCtx, profile)
	if err != nil {
		return nil, fmt.Errorf("sending profile: %w", err)
	}
	return ack, nil
}

// SendTelemetry sends a single anomaly event to the hub and returns the Ack.
func (c *HubClient) SendTelemetry(
	ctx context.Context, event *pb.TelemetryEvent,
) (*pb.Ack, error) {
	sendCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	ack, err := c.ingest.SendTelemetry(sendCtx, event)
	if err != nil {
		return nil, fmt.Errorf("sending telemetry: %w", err)
	}
	return ack, nil
}

// Close shuts down the connection to the hub.
func (c *HubClient) Close() error {
	return c.conn.Close()
}
