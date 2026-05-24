package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func main() {
	fmt.Println("Sentinel Node — starting up...")

	// In production, node_id will be persisted to disk at install time.
	// For now we generate a fresh one on every startup.
	nodeID := uuid.NewString()
	fmt.Printf("Node ID: %s\n\n", nodeID)

	// Collect the initial snapshot of the environment.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Collecting system profile...")
	start := time.Now()
	profile := CollectProfile(ctx, nodeID)
	elapsed := time.Since(start)

	// Human-readable dump of the collected profile.
	printProfile(profile)

	fmt.Printf("\nProfile collected in %s\n", elapsed.Round(time.Millisecond))
}
