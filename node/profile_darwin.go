//go:build darwin

package main

import pb "github.com/sentinel/sentinel/gen/sentinelv1"

// Questo file viene compilato SOLO su macOS.
// Le funzioni qui sono versioni minime: servono solo a far girare
// il nodo durante lo sviluppo sul Mac. La logica vera è nel file _linux.

func collectServices() []*pb.Service             { return nil }
func collectPackages() []*pb.Package             { return nil }
func collectRuntimes() []*pb.Runtime             { return nil }
func collectListeningPorts() []*pb.ListeningPort { return nil }
func collectContainers() []*pb.Container         { return nil }
func collectFailedUnits() []*pb.FailedUnit       { return nil }
func collectKernelMessages() []*pb.KernelMessage { return nil }
func collectCertificates() []*pb.Certificate     { return nil }
func collectPressure() *pb.ResourcePressure      { return &pb.ResourcePressure{} }
func collectTimeSync() *pb.TimeSync              { return &pb.TimeSync{} }
func collectLimits() *pb.SystemLimits            { return &pb.SystemLimits{} }
func platformCPUModel() string                   { return "" }
