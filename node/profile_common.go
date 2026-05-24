package main

import (
	"context"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// nodeVersion is the daemon version. Bumped on every release.
const nodeVersion = "0.1.0"

// CollectProfile captures a full snapshot of the environment.
// It runs once, at node startup.
func CollectProfile(ctx context.Context, nodeID string) *pb.SystemProfile {
	profile := &pb.SystemProfile{
		ProfileId:      uuid.NewString(),
		CapturedAt:     timestamppb.Now(),
		NodeId:         nodeID,
		NodeVersion:    nodeVersion,
		RunningAsUser:  currentUser(),
		Os:             collectOS(),
		Hardware:       collectHardware(ctx),
		Filesystems:    collectFilesystems(),
		TopProcesses:   collectTopProcesses(),
		Interfaces:     collectInterfaces(),
		Services:       collectServices(),
		Packages:       collectPackages(),
		Runtimes:       collectRuntimes(),
		ListeningPorts: collectListeningPorts(),
		Containers:     collectContainers(),
		FailedUnits:    collectFailedUnits(),
		KernelMessages: collectKernelMessages(),
		Certificates:   collectCertificates(),
		Pressure:       collectPressure(),
		TimeSync:       collectTimeSync(),
		Limits:         collectLimits(),
	}
	return profile
}

// collectOS gathers operating system and kernel information.
func collectOS() *pb.OSInfo {
	info, err := host.Info()
	if err != nil {
		return &pb.OSInfo{}
	}
	return &pb.OSInfo{
		Distribution:  info.Platform,
		Version:       info.PlatformVersion,
		KernelVersion: info.KernelVersion,
		Architecture:  info.KernelArch,
		Hostname:      info.Hostname,
		UptimeSeconds: int64(info.Uptime),
		Timezone:      currentTimezone(),
	}
}

// collectHardware gathers physical resource information.
func collectHardware(ctx context.Context) *pb.HardwareInfo {
	hw := &pb.HardwareInfo{
		CpuCores: int32(runtime.NumCPU()),
	}

	if cpus, err := cpu.InfoWithContext(ctx); err == nil && len(cpus) > 0 {
		hw.CpuModel = cpus[0].ModelName
	}
	// On some platforms (notably ARM Linux) the model name is empty.
	// platformCPUModel provides a platform-specific fallback.
	if hw.CpuModel == "" {
		hw.CpuModel = platformCPUModel()
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		hw.RamTotalBytes = int64(vm.Total)
	}
	if usage, err := disk.Usage("/"); err == nil {
		hw.DiskTotalBytes = int64(usage.Total)
	}
	return hw
}

// collectFilesystems collects every mounted filesystem and its health state.
func collectFilesystems() []*pb.FilesystemInfo {
	partitions, err := disk.Partitions(true)
	if err != nil {
		return nil
	}

	var result []*pb.FilesystemInfo
	for _, p := range partitions {
		if isVirtualFS(p.Fstype) {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		if usage.Total == 0 {
			continue
		}
		result = append(result, &pb.FilesystemInfo{
			MountPoint:    p.Mountpoint,
			Device:        p.Device,
			FsType:        p.Fstype,
			TotalBytes:    int64(usage.Total),
			UsedBytes:     int64(usage.Used),
			UsedPercent:   usage.UsedPercent,
			InodesTotal:   int64(usage.InodesTotal),
			InodesUsed:    int64(usage.InodesUsed),
			InodesPercent: usage.InodesUsedPercent,
			ReadOnly:      isReadOnly(p.Opts),
		})
	}
	return result
}

// isVirtualFS reports whether a filesystem type is a kernel-virtual one
// (sysfs, cgroup, proc...) that carries no real storage worth profiling.
func isVirtualFS(fsType string) bool {
	virtual := map[string]bool{
		"sysfs": true, "proc": true, "devpts": true, "cgroup": true,
		"cgroup2": true, "mqueue": true, "devtmpfs": true, "securityfs": true,
		"pstore": true, "bpf": true, "tracefs": true, "debugfs": true,
		"hugetlbfs": true, "fusectl": true, "configfs": true, "binfmt_misc": true,
		"autofs": true, "nsfs": true,
	}
	return virtual[fsType]
}

// collectTopProcesses collects the running processes.
func collectTopProcesses() []*pb.Process {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}

	var result []*pb.Process
	for _, p := range procs {
		name, _ := p.Name()
		cpuPct, _ := p.CPUPercent()
		memInfo, _ := p.MemoryInfo()
		username, _ := p.Username()

		var memBytes int64
		if memInfo != nil {
			memBytes = int64(memInfo.RSS)
		}

		result = append(result, &pb.Process{
			Pid:         p.Pid,
			Name:        name,
			CpuPercent:  cpuPct,
			MemoryBytes: memBytes,
			User:        username,
		})
	}
	return result
}

// collectInterfaces collects the network interfaces.
func collectInterfaces() []*pb.NetworkInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []*pb.NetworkInterface
	for _, iface := range ifaces {
		var ips []string
		for _, addr := range iface.Addrs {
			ips = append(ips, addr.Addr)
		}
		result = append(result, &pb.NetworkInterface{
			Name:        iface.Name,
			IpAddresses: ips,
			MacAddress:  iface.HardwareAddr,
			IsUp:        isInterfaceUp(iface.Flags),
		})
	}
	return result
}

// --- helpers ---

func isReadOnly(opts []string) bool {
	for _, o := range opts {
		if o == "ro" {
			return true
		}
	}
	return false
}

func isInterfaceUp(flags []string) bool {
	for _, f := range flags {
		if f == "up" {
			return true
		}
	}
	return false
}

func currentTimezone() string {
	zone, _ := time.Now().Zone()
	return zone
}
