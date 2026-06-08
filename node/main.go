package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// hubAddress is where the node reaches the hub.
// In production this comes from a config file; hardcoded for now.
const hubAddress = "localhost:50051"

// nodeIDFile is where the node persists its identity, so it keeps the
// same node_id across restarts instead of becoming a "new" node.
const nodeIDFile = ".sentinel-node-id"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	log.Info("Sentinel Node — starting up")

	// Load a stable identity from disk, or create one on first run.
	nodeID := loadOrCreateNodeID(log)
	log.Info("node identity", "node_id", nodeID)

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

// loadOrCreateNodeID returns a stable node identity. On first run it
// generates a UUID and writes it to nodeIDFile; on later runs it reads
// the existing one back, so the node keeps the same identity across
// restarts. In production this lives at a fixed install path.
func loadOrCreateNodeID(log *slog.Logger) string {
	path := nodeIDFilePath()

	// Try to read an existing identity.
	if data, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(data))
		if _, err := uuid.Parse(id); err == nil {
			return id
		}
		log.Warn("stored node id is invalid, generating a new one", "path", path)
	}

	// First run (or unreadable): generate and persist a fresh identity.
	id := uuid.NewString()
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		// Non-fatal: fall back to an in-memory identity for this run.
		log.Warn("could not persist node id, using ephemeral identity",
			"path", path, "error", err)
	} else {
		log.Info("generated new persistent node id", "path", path)
	}
	return id
}

// nodeIDFilePath resolves where the identity file lives. It prefers the
// user's home directory; if unavailable, it falls back to the working
// directory.
func nodeIDFilePath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, nodeIDFile)
	}
	return nodeIDFile
}
