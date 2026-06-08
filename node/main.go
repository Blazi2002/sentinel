package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// hubAddress is where the node reaches the hub.
// In production this comes from a config file; hardcoded for now.
const hubAddress = "localhost:50051"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	log.Info("Sentinel Node — starting up")

	// In production, node_id will be persisted to disk at install time.
	// For now we generate a fresh one on every startup.
	nodeID := uuid.NewString()
	log.Info("node identity assigned", "node_id", nodeID)

	// Root context: cancelled on shutdown signal, stops everything.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to the hub.
	log.Info("connecting to hub", "address", hubAddress)
	hub, err := NewHubClient(hubAddress)
	if err != nil {
		log.Error("could not create hub client", "error", err)
		os.Exit(1)
	}
	defer hub.Close()

	// Startup snapshot: collect the environment profile and send it once.
	profileCtx, profileCancel := context.WithTimeout(ctx, 30*time.Second)
	log.Info("collecting system profile")
	profile := CollectProfile(profileCtx, nodeID)
	profileCancel()

	ack, err := hub.SendProfile(ctx, profile)
	if err != nil {
		log.Error("failed to send startup profile", "error", err)
		os.Exit(1)
	}
	log.Info("startup profile sent", "receipt_id", ack.GetReceiptId())

	// The executor runs approved plans. DRY-RUN by default: it logs what
	// it would do without touching the system. Switch to ModeLive only
	// in a controlled environment.
	executor := NewExecutor(ModeDryRun, log)
	log.Info("executor ready", "mode", executor.mode.String())

	// Start the live monitoring loop in the background.
	monitor := NewMonitor(nodeID, hub, executor, log)
	go monitor.Run(ctx)

	// Wait for Ctrl+C or a termination signal, then shut down cleanly.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutdown signal received, stopping")
	cancel()
	// Give the monitor a moment to finish its current cycle.
	time.Sleep(500 * time.Millisecond)
	log.Info("node stopped")
}
