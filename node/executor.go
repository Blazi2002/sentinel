package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// ExecMode controls whether the executor actually runs commands.
type ExecMode int

const (
	// ModeDryRun logs what would be executed without touching the system.
	// This is the SAFE DEFAULT.
	ModeDryRun ExecMode = iota
	// ModeLive actually executes commands via the system shell.
	// Only used when explicitly enabled.
	ModeLive
)

func (m ExecMode) String() string {
	if m == ModeLive {
		return "live"
	}
	return "dry-run"
}

// PlannedCommand is one command to execute, paired with the policy
// engine's verdict for it. The executor only runs "allow" commands.
type PlannedCommand struct {
	Order   int32
	Command string
	Action  string // "allow", "review", or "block"
}

// CommandOutcome is the result of attempting one command.
type CommandOutcome struct {
	Order    int32
	Command  string
	Executed bool   // whether it actually ran (or would have, in dry-run)
	Skipped  bool   // true if skipped because not "allow"
	Success  bool   // whether it exited successfully
	Output   string // captured output (or dry-run note)
	Err      string // error message, if any
}

// Executor runs approved remediation plans on the local system.
type Executor struct {
	mode ExecMode
	log  *slog.Logger
}

// NewExecutor builds an executor in the given mode.
func NewExecutor(mode ExecMode, log *slog.Logger) *Executor {
	return &Executor{mode: mode, log: log}
}

// ExecutePlan runs every "allow" command in order, skipping any command
// the policy engine did not allow. It never runs "review" or "block"
// commands, regardless of operator approval: the deterministic verdict
// is the final technical gate.
func (e *Executor) ExecutePlan(
	ctx context.Context, commands []PlannedCommand,
) []CommandOutcome {
	var outcomes []CommandOutcome

	for _, c := range commands {
		// The safety gate: only "allow" commands may run.
		if c.Action != "allow" {
			e.log.Info("skipping non-allow command",
				"order", c.Order, "action", c.Action, "command", c.Command)
			outcomes = append(outcomes, CommandOutcome{
				Order:   c.Order,
				Command: c.Command,
				Skipped: true,
				Output:  fmt.Sprintf("skipped: policy verdict was %q", c.Action),
			})
			continue
		}

		outcomes = append(outcomes, e.runOne(ctx, c))
	}
	return outcomes
}

// runOne executes (or simulates) a single allowed command.
func (e *Executor) runOne(ctx context.Context, c PlannedCommand) CommandOutcome {
	outcome := CommandOutcome{Order: c.Order, Command: c.Command, Executed: true}

	if e.mode == ModeDryRun {
		e.log.Info("DRY-RUN: would execute",
			"order", c.Order, "command", c.Command)
		outcome.Success = true
		outcome.Output = "[dry-run] command not actually executed"
		return outcome
	}

	// --- ModeLive: actually execute via the shell ---
	e.log.Warn("LIVE: executing command",
		"order", c.Order, "command", c.Command)

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "sh", "-c", c.Command)
	out, err := cmd.CombinedOutput()
	outcome.Output = strings.TrimSpace(string(out))
	if err != nil {
		outcome.Success = false
		outcome.Err = err.Error()
		e.log.Error("command failed",
			"order", c.Order, "command", c.Command, "error", err)
		return outcome
	}
	outcome.Success = true
	return outcome
}
