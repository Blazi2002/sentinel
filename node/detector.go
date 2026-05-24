package main

import (
	"fmt"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// Thresholds define when a metric is considered anomalous.
// In production these will be configurable per node; hardcoded for now.
const (
	cpuPressureThreshold  = 80.0 // PSI stall percentage
	memUsedPctThreshold   = 90.0 // percent of RAM in use
	diskUsedPctThreshold  = 90.0 // percent of any filesystem in use
	inodeUsedPctThreshold = 90.0 // percent of inodes in use
)

// Anomaly is a single detected problem, before it becomes a TelemetryEvent.
type Anomaly struct {
	Severity pb.Severity
	Source   pb.Source
	Summary  string             // short human-readable description
	Metrics  []*pb.MetricSample // the measurements that triggered it
	Labels   map[string]string  // extra context
}

// DetectAnomalies inspects the current system state and returns
// every anomaly found. An empty result means the system is healthy.
func DetectAnomalies() []Anomaly {
	var found []Anomaly

	if a := checkMemory(); a != nil {
		found = append(found, *a)
	}
	if a := checkDisks(); a != nil {
		found = append(found, *a)
	}
	return found
}

// checkMemory flags excessive RAM usage.
func checkMemory() *Anomaly {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return nil
	}
	if vm.UsedPercent < memUsedPctThreshold {
		return nil
	}
	return &Anomaly{
		Severity: pb.Severity_SEVERITY_WARNING,
		Source:   pb.Source_SOURCE_METRICS,
		Summary: fmt.Sprintf("memory usage at %.1f%% (threshold %.0f%%)",
			vm.UsedPercent, memUsedPctThreshold),
		Metrics: []*pb.MetricSample{
			{Name: "memory.used.percent", Value: vm.UsedPercent, Unit: "percent"},
		},
	}
}

// checkDisks flags any real filesystem running out of space or inodes.
func checkDisks() *Anomaly {
	partitions, err := disk.Partitions(true)
	if err != nil {
		return nil
	}
	for _, p := range partitions {
		if isVirtualFS(p.Fstype) || !isMonitorableMount(p.Mountpoint, p.Opts) {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil || usage.Total == 0 {
			continue
		}

		if usage.UsedPercent >= diskUsedPctThreshold {
			return &Anomaly{
				Severity: pb.Severity_SEVERITY_ERROR,
				Source:   pb.Source_SOURCE_METRICS,
				Summary: fmt.Sprintf("filesystem %s at %.1f%% full",
					p.Mountpoint, usage.UsedPercent),
				Metrics: []*pb.MetricSample{
					{Name: "disk.used.percent", Value: usage.UsedPercent, Unit: "percent"},
				},
				Labels: map[string]string{"mount_point": p.Mountpoint},
			}
		}

		if usage.InodesUsedPercent >= inodeUsedPctThreshold {
			return &Anomaly{
				Severity: pb.Severity_SEVERITY_ERROR,
				Source:   pb.Source_SOURCE_METRICS,
				Summary: fmt.Sprintf("filesystem %s at %.1f%% inodes used",
					p.Mountpoint, usage.InodesUsedPercent),
				Metrics: []*pb.MetricSample{
					{Name: "disk.inodes.percent", Value: usage.InodesUsedPercent, Unit: "percent"},
				},
				Labels: map[string]string{"mount_point": p.Mountpoint},
			}
		}
	}
	return nil
}

// isMonitorableMount reports whether a mount point is a real filesystem
// worth alerting on. Pseudo-filesystems (/dev) and read-only system
// volumes are always "full" by design and would cause false positives.
func isMonitorableMount(mountPoint string, opts []string) bool {
	// Read-only filesystems are typically system volumes, not user storage.
	if isReadOnly(opts) {
		return false
	}
	// Mount points that are never real user storage.
	ignored := []string{"/dev", "/System/Volumes/VM", "/System/Volumes/Preboot",
		"/System/Volumes/Update", "/private/var/vm"}
	for _, prefix := range ignored {
		if mountPoint == prefix || hasPathPrefix(mountPoint, prefix) {
			return false
		}
	}
	return true
}

// hasPathPrefix reports whether path is under the given directory prefix.
func hasPathPrefix(path, prefix string) bool {
	return len(path) > len(prefix) &&
		path[:len(prefix)] == prefix &&
		path[len(prefix)] == '/'
}
