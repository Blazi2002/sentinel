package reasoning

import (
	"fmt"
	"strings"

	pb "github.com/sentinel/sentinel/gen/sentinelv1"
)

// systemPrompt defines the model's role and the strict shape of its
// answer. It is sent as the "system" message on every request.
const systemPrompt = `You are an autonomous Site Reliability Engineering (SRE) assistant.
You analyze a single infrastructure anomaly and produce a remediation plan.

You MUST reply with a single JSON object and nothing else. The JSON object
must have exactly these fields:

{
  "root_cause": "<concise technical explanation of the most likely cause>",
  "risk_level": "<one of: LOW, MEDIUM, HIGH, CRITICAL>",
  "confidence": <a number between 0.0 and 1.0>,
  "commands": [
    {
      "command": "<a single shell command to run>",
      "explanation": "<what this command does and why>",
      "rollback_command": "<a command that undoes this, or empty string>"
    }
  ]
}

Rules you must follow:
- Propose the smallest, safest set of commands that addresses the cause.
- Never propose destructive commands (no rm -rf, no mkfs, no dd to devices).
- Never propose commands that fetch content from the internet.
- Never leave placeholders like <PID> in a command; use concrete values.
- If you are unsure, lower the confidence value accordingly.
- Prefer reversible actions and always fill rollback_command when one exists.
- Order commands by execution order.`

// BuildUserPrompt turns a telemetry event into the user-facing prompt
// describing the anomaly the model must diagnose.
func BuildUserPrompt(event *pb.TelemetryEvent) string {
	var b strings.Builder

	b.WriteString("An anomaly was detected on a production server.\n\n")
	b.WriteString("ANOMALY DETAILS\n")
	b.WriteString(fmt.Sprintf("- Severity: %s\n", severityText(event.GetSeverity())))
	b.WriteString(fmt.Sprintf("- Source: %s\n", sourceText(event.GetSource())))
	b.WriteString(fmt.Sprintf("- Summary: %s\n", event.GetRawPayload()))

	// Attach any measurements that triggered the anomaly.
	if metrics := event.GetMetrics(); len(metrics) > 0 {
		b.WriteString("\nMEASUREMENTS\n")
		for _, m := range metrics {
			b.WriteString(fmt.Sprintf("- %s = %.2f %s\n",
				m.GetName(), m.GetValue(), m.GetUnit()))
		}
	}

	labels := event.GetLabels()

	// The top memory-consuming processes are the single most useful
	// piece of context for a diagnosis: give them their own section
	// and tell the model explicitly to use them.
	if procs, ok := labels["top_memory_processes"]; ok && procs != "" {
		b.WriteString("\nTOP MEMORY-CONSUMING PROCESSES (at time of detection)\n")
		for _, entry := range strings.Split(procs, " | ") {
			b.WriteString(fmt.Sprintf("- %s\n", entry))
		}
		b.WriteString("Base your root cause analysis on these processes: " +
			"identify which one is the likely culprit.\n")
	}

	// Attach any remaining contextual labels.
	if len(labels) > 0 {
		var wrote bool
		for k, v := range labels {
			if k == "top_memory_processes" {
				continue // already shown above
			}
			if !wrote {
				b.WriteString("\nCONTEXT\n")
				wrote = true
			}
			b.WriteString(fmt.Sprintf("- %s: %s\n", k, v))
		}
	}

	b.WriteString("\nProduce the remediation plan as the JSON object specified.")
	return b.String()
}

// severityText renders a Severity enum as a plain word for the prompt.
func severityText(s pb.Severity) string {
	switch s {
	case pb.Severity_SEVERITY_INFO:
		return "INFO"
	case pb.Severity_SEVERITY_WARNING:
		return "WARNING"
	case pb.Severity_SEVERITY_ERROR:
		return "ERROR"
	case pb.Severity_SEVERITY_CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// sourceText renders a Source enum as a plain word for the prompt.
func sourceText(s pb.Source) string {
	switch s {
	case pb.Source_SOURCE_JOURNALD:
		return "system logs (journald)"
	case pb.Source_SOURCE_DOCKER:
		return "container runtime (Docker)"
	case pb.Source_SOURCE_METRICS:
		return "system metrics"
	default:
		return "unknown source"
	}
}
