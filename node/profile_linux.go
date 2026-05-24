//go:build linux

package main

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// This file is compiled ONLY on Linux.
// It holds the real data collection: systemd, packages, kernel, PSI, limits.

// collectServices reads systemd services via systemctl.
func collectServices() []*pb.Service {
	out, err := exec.Command("systemctl", "list-units",
		"--type=service", "--all", "--no-legend", "--plain").Output()
	if err != nil {
		return nil
	}

	var services []*pb.Service
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		services = append(services, &pb.Service{
			Name:        fields[0],
			ActiveState: fields[2],
			SubState:    fields[3],
			Enabled:     isUnitEnabled(fields[0]),
		})
	}
	return services
}

// isUnitEnabled reports whether a systemd unit starts at boot.
func isUnitEnabled(name string) bool {
	out, err := exec.Command("systemctl", "is-enabled", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "enabled"
}

// collectFailedUnits reads systemd units in a failed state.
func collectFailedUnits() []*pb.FailedUnit {
	out, err := exec.Command("systemctl", "list-units",
		"--state=failed", "--no-legend", "--plain").Output()
	if err != nil {
		return nil
	}

	var units []*pb.FailedUnit
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		units = append(units, &pb.FailedUnit{
			Name:        fields[0],
			Description: strings.Join(fields[4:], " "),
			Result:      fields[3],
		})
	}
	return units
}

// collectPackages reads installed packages (RPM or dpkg).
func collectPackages() []*pb.Package {
	if pkgs := collectRPM(); pkgs != nil {
		return pkgs
	}
	return collectDPKG()
}

func collectRPM() []*pb.Package {
	out, err := exec.Command("rpm", "-qa",
		"--queryformat", "%{NAME} %{VERSION}\n").Output()
	if err != nil {
		return nil
	}
	return parsePackageLines(string(out))
}

func collectDPKG() []*pb.Package {
	out, err := exec.Command("dpkg-query", "-W",
		"-f=${Package} ${Version}\n").Output()
	if err != nil {
		return nil
	}
	return parsePackageLines(string(out))
}

func parsePackageLines(text string) []*pb.Package {
	var pkgs []*pb.Package
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		pkgs = append(pkgs, &pb.Package{
			Name:    fields[0],
			Version: fields[1],
		})
	}
	return pkgs
}

// collectKernelMessages reads critical messages from the kernel ring buffer.
func collectKernelMessages() []*pb.KernelMessage {
	out, err := exec.Command("dmesg", "--level=err,crit,emerg",
		"--time-format=iso").Output()
	if err != nil {
		return nil
	}

	var msgs []*pb.KernelMessage
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		msgs = append(msgs, &pb.KernelMessage{
			Severity: "err",
			Message:  line,
		})
	}
	return msgs
}

// collectPressure reads kernel PSI (Pressure Stall Information) metrics.
func collectPressure() *pb.ResourcePressure {
	p := &pb.ResourcePressure{}

	if vm := readMemInfo(); vm != nil {
		p.RamAvailableBytes = vm["MemAvailable"]
		p.SwapTotalBytes = vm["SwapTotal"]
		p.SwapUsedBytes = vm["SwapTotal"] - vm["SwapFree"]
	}

	p.CpuPressure = readPSI("/proc/pressure/cpu")
	p.MemoryPressure = readPSI("/proc/pressure/memory")
	p.IoPressure = readPSI("/proc/pressure/io")
	return p
}

// readPSI extracts the "avg10" stall percentage from a PSI file.
func readPSI(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "some") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "avg10=") {
				v, _ := strconv.ParseFloat(strings.TrimPrefix(field, "avg10="), 64)
				return v
			}
		}
	}
	return 0
}

// readMemInfo reads /proc/meminfo and returns values in bytes.
func readMemInfo() map[string]int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	result := make(map[string]int64)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		kb, _ := strconv.ParseInt(fields[1], 10, 64)
		result[key] = kb * 1024 // meminfo values are in kB
	}
	return result
}

// collectTimeSync checks the system clock synchronization state.
func collectTimeSync() *pb.TimeSync {
	ts := &pb.TimeSync{}
	out, err := exec.Command("timedatectl", "show").Output()
	if err != nil {
		return ts
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "NTPSynchronized=") {
			ts.Synchronized = strings.TrimPrefix(line, "NTPSynchronized=") == "yes"
		}
	}
	ts.SyncSource = "systemd-timesyncd"
	return ts
}

// collectLimits reads system limits (file descriptors, processes).
func collectLimits() *pb.SystemLimits {
	limits := &pb.SystemLimits{}

	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		limits.MaxOpenFiles = int64(rl.Cur)
	}
	return limits
}

// platformCPUModel reads the CPU model from /proc/cpuinfo on Linux.
// On ARM the standard model field is often empty, so we look for
// alternative keys that ARM kernels populate.
func platformCPUModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	keys := []string{"model name", "Model", "Hardware", "Processor"}
	for _, line := range strings.Split(string(data), "\n") {
		for _, key := range keys {
			if strings.HasPrefix(line, key) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if v != "" {
						return v
					}
				}
			}
		}
	}
	return ""
}

// collectRuntimes, collectListeningPorts, collectContainers and collectCertificates
// will be implemented in later steps. For now they return empty
// so the node compiles and runs.
func collectRuntimes() []*pb.Runtime             { return nil }
func collectListeningPorts() []*pb.ListeningPort { return nil }
func collectContainers() []*pb.Container         { return nil }
func collectCertificates() []*pb.Certificate     { return nil }
