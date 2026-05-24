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
	// listenAddress is the host:port the hub listens on for nodes.
	listenAddress = "0.0.0.0:50051"

	// dbConnString points at the local PostgreSQL instance.
	// In production this comes from Vault, not from source.
	dbConnString = "postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable"

	// llmModel is the Ollama model used for reasoning.
	llmModel = "qwen2.5-coder:7b"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	log.Info("Sentinel Hub — starting up", "address", listenAddress)

	ctx := context.Background()

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

	// Open the TCP socket for gRPC.
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Error("failed to open listening socket", "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterIngestServiceServer(grpcServer, newIngestServer(log, pipeline))

	go func() {
		log.Info("hub is ready and accepting connections")
		if err := grpcServer.Serve(listener); err != nil {
			log.Error("gRPC server stopped", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for a shutdown signal, then stop cleanly.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutdown signal received, stopping gracefully")
	grpcServer.GracefulStop()
	log.Info("hub stopped")
}
