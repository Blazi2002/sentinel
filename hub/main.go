package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
	"github.com/sentinel/sentinel/policy"
	"github.com/sentinel/sentinel/reasoning"
)

const (
	// grpcAddress is where nodes connect (gRPC).
	grpcAddress = "0.0.0.0:50051"

	// httpAddress is where the operator dashboard connects (HTTP API).
	httpAddress = "0.0.0.0:8080"

	// dbConnString points at the local PostgreSQL instance.
	// In production this comes from Vault, not from source.
	dbConnString = "postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable"

	// llmModel is the Ollama model used for reasoning.
	llmModel = "qwen2.5-coder:7b"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	log.Info("Sentinel Hub — starting up")

	// Root context: cancelled on shutdown signal, stops everything.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL.
	log.Info("connecting to database")
	store, err := NewStore(ctx, dbConnString)
	if err != nil {
		log.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	log.Info("database connected")

	// Set up the reasoning engine and verify Ollama is reachable.
	reasoner := reasoning.NewReasoner(llmModel)
	if err := reasoner.Health(ctx); err != nil {
		log.Error("reasoning engine not reachable", "error", err)
		log.Error("is `ollama serve` running?")
		os.Exit(1)
	}
	log.Info("reasoning engine ready", "model", llmModel)

	// Build the processing pipeline: reasoning -> policy -> persistence.
	policyEngine := policy.NewEngine()
	pipeline := NewPipeline(reasoner, policyEngine, store, log)

	// --- gRPC server (for nodes) ---
	listener, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		log.Error("failed to open gRPC socket", "error", err)
		os.Exit(1)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterIngestServiceServer(grpcServer, newIngestServer(log, pipeline))

	go func() {
		log.Info("gRPC server listening", "address", grpcAddress)
		if err := grpcServer.Serve(listener); err != nil {
			log.Error("gRPC server stopped", "error", err)
			os.Exit(1)
		}
	}()

	// --- HTTP API server (for the dashboard) ---
	api := newAPIServer(store, log)
	go startAPIServer(ctx, httpAddress, api.routes(), log)

	log.Info("hub is ready")

	// Wait for a shutdown signal, then stop cleanly.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutdown signal received, stopping gracefully")
	cancel() // stops the HTTP API
	grpcServer.GracefulStop()
	log.Info("hub stopped")
}
