package main

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// listenAddress is the host:port the hub listens on.
// 0.0.0.0 means "accept connections on every network interface".
const listenAddress = "0.0.0.0:50051"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	log.Info("Sentinel Hub — starting up", "address", listenAddress)

	// Open the TCP socket the hub will accept connections on.
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Error("failed to open listening socket", "error", err)
		os.Exit(1)
	}

	// Build the gRPC server and register our ingest service on it.
	grpcServer := grpc.NewServer()
	pb.RegisterIngestServiceServer(grpcServer, newIngestServer(log))

	// Run the server in a separate goroutine so main can wait
	// for a shutdown signal below.
	go func() {
		log.Info("hub is ready and accepting connections")
		if err := grpcServer.Serve(listener); err != nil {
			log.Error("gRPC server stopped", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for Ctrl+C or a termination signal, then shut down cleanly.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutdown signal received, stopping gracefully")
	grpcServer.GracefulStop()
	log.Info("hub stopped")
}
