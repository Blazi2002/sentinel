package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
)

// hubAddress is where the node reaches the hub.
// In production this comes from a config file; hardcoded for now.
const hubAddress = "localhost:50051"

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

	// Connect to the hub and send the profile.
	fmt.Printf("\nConnecting to hub at %s...\n", hubAddress)
	client, err := NewHubClient(hubAddress)
	if err != nil {
		fmt.Printf("ERROR: could not create hub client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Println("Sending profile to hub...")
	ack, err := client.SendProfile(ctx, profile)
	if err != nil {
		fmt.Printf("ERROR: failed to send profile: %v\n", err)
		os.Exit(1)
	}

	// The hub accepted the profile — print the acknowledgement.
	fmt.Println("Profile sent successfully.")
	fmt.Printf("  Hub receipt ID: %s\n", ack.GetReceiptId())
	fmt.Printf("  Hub message:    %s\n", ack.GetMessage())
}
