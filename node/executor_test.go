package main

import (
	"context"
	"log/slog"
	"testing"
)

// testExecutor builds a dry-run executor with a silent logger.
func testExecutor() *Executor {
	return NewExecutor(ModeDryRun, slog.New(slog.NewTextHandler(discard{}, nil)))
}

// discard is an io.Writer that throws away log output during tests.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// TestOnlyAllowCommandsAreExecuted is the core safety guarantee:
// commands the policy engine marked "review" or "block" must NEVER be
// executed, even when handed directly to the executor.
func TestOnlyAllowCommandsAreExecuted(t *testing.T) {
	e := testExecutor()

	plan := []PlannedCommand{
		{Order: 1, Command: "systemctl status nginx", Action: "allow"},
		{Order: 2, Command: "kill -9 1234", Action: "review"},
		{Order: 3, Command: "rm -rf /data", Action: "block"},
		{Order: 4, Command: "df -h", Action: "allow"},
	}

	outcomes := e.ExecutePlan(context.Background(), plan)

	if len(outcomes) != 4 {
		t.Fatalf("expected 4 outcomes, got %d", len(outcomes))
	}

	// Commands 1 and 4 (allow) must have executed.
	for _, idx := range []int{0, 3} {
		if outcomes[idx].Skipped {
			t.Errorf("allow command %q was skipped",
				outcomes[idx].Command)
		}
		if !outcomes[idx].Executed {
			t.Errorf("allow command %q did not execute",
				outcomes[idx].Command)
		}
	}

	// Commands 2 (review) and 3 (block) must have been skipped.
	for _, idx := range []int{1, 2} {
		if !outcomes[idx].Skipped {
			t.Errorf("non-allow command %q was NOT skipped (action=%s)",
				outcomes[idx].Command, plan[idx].Action)
		}
		if outcomes[idx].Executed {
			t.Errorf("non-allow command %q was executed — SAFETY VIOLATION",
				outcomes[idx].Command)
		}
	}
}

// TestDryRunNeverExecutes verifies dry-run mode reports success without
// actually running anything.
func TestDryRunNeverExecutes(t *testing.T) {
	e := testExecutor()
	plan := []PlannedCommand{
		{Order: 1, Command: "echo hello", Action: "allow"},
	}
	outcomes := e.ExecutePlan(context.Background(), plan)
	if !outcomes[0].Success {
		t.Errorf("dry-run allow command should report success")
	}
	if outcomes[0].Output == "" {
		t.Errorf("dry-run should leave a note in Output")
	}
}
