package main

import (
	"fmt"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// printProfile prints the SystemProfile in human-readable form.
// This is a development aid: in production the profile travels over gRPC.
func printProfile(p *pb.SystemProfile) {
	line := "------------------------------------------------------------"

	fmt.Println(line)
	fmt.Println("SYSTEM PROFILE")
	fmt.Println(line)

	if os := p.GetOs(); os != nil {
		fmt.Printf("OS:         %s %s\n", os.GetDistribution(), os.GetVersion())
		fmt.Printf("Kernel:     %s (%s)\n", os.GetKernelVersion(), os.GetArchitecture())
		fmt.Printf("Hostname:   %s\n", os.GetHostname())
		fmt.Printf("Uptime:     %d hours\n", os.GetUptimeSeconds()/3600)
	}

	if hw := p.GetHardware(); hw != nil {
		fmt.Println(line)
		fmt.Printf("CPU:        %d cores — %s\n", hw.GetCpuCores(), hw.GetCpuModel())
		fmt.Printf("RAM:        %.1f GB\n", bytesToGB(hw.GetRamTotalBytes()))
		fmt.Printf("Disk:       %.1f GB\n", bytesToGB(hw.GetDiskTotalBytes()))
	}

	fmt.Println(line)
	fmt.Printf("Mounted filesystems:  %d\n", len(p.GetFilesystems()))
	fmt.Printf("Processes detected:   %d\n", len(p.GetTopProcesses()))
	fmt.Printf("Network interfaces:   %d\n", len(p.GetInterfaces()))
	fmt.Printf("systemd services:     %d\n", len(p.GetServices()))
	fmt.Printf("Packages:             %d\n", len(p.GetPackages()))
	fmt.Printf("Failed units:         %d\n", len(p.GetFailedUnits()))
	fmt.Printf("Kernel messages:      %d\n", len(p.GetKernelMessages()))

	if pr := p.GetPressure(); pr != nil {
		fmt.Println(line)
		fmt.Printf("RAM available:        %.1f GB\n", bytesToGB(pr.GetRamAvailableBytes()))
		fmt.Printf("CPU pressure:         %.1f\n", pr.GetCpuPressure())
		fmt.Printf("Memory pressure:      %.1f\n", pr.GetMemoryPressure())
	}

	fmt.Println(line)
}

func bytesToGB(b int64) float64 {
	return float64(b) / (1024 * 1024 * 1024)
}
