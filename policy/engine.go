package policy

import "fmt"

// Verdict is the engine's overall decision for a whole remediation plan.
type Verdict int

const (
	// VerdictApproved: every command is safe to run.
	VerdictApproved Verdict = iota
	// VerdictNeedsReview: at least one command needs human approval,
	// and none is outright forbidden.
	VerdictNeedsReview
	// VerdictBlocked: at least one command is forbidden; the whole
	// plan is rejected and must not run.
	VerdictBlocked
)

// String renders a Verdict for logs and decisions.
func (v Verdict) String() string {
	switch v {
	case VerdictApproved:
		return "approved"
	case VerdictNeedsReview:
		return "needs_review"
	case VerdictBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// Finding records why one command was judged the way it was.
type Finding struct {
	CommandOrder int    // 1-based position of the command in the plan
	CommandText  string // the raw command this finding refers to
	RuleID       string // the rule that matched, empty if none did
	Description  string // human-readable explanation
	Action       Action // the action this command triggered
}

// Decision is the engine's full evaluation of a remediation plan.
type Decision struct {
	Verdict  Verdict
	Findings []Finding // one entry per command, in plan order
}

// Engine evaluates remediation plans against the policy rule set.
// It holds no mutable state, so a single Engine is safe to reuse.
type Engine struct {
	rules []ruleDefinition
}

// NewEngine builds an engine backed by the default rule set.
func NewEngine() *Engine {
	return &Engine{rules: ruleSet}
}

// Evaluate inspects an ordered list of raw command strings and returns
// the overall Decision. Commands are 1-indexed in the findings.
func (e *Engine) Evaluate(commands []string) Decision {
	var findings []Finding
	worst := VerdictApproved

	for i, raw := range commands {
		f := e.evaluateOne(i+1, raw)
		findings = append(findings, f)

		// Escalate the overall verdict to the worst command seen.
		if v := verdictForAction(f.Action); v > worst {
			worst = v
		}
	}

	return Decision{Verdict: worst, Findings: findings}
}

// evaluateOne runs the rule set against a single command.
// The first matching rule wins (rules are ordered most-dangerous first).
func (e *Engine) evaluateOne(order int, raw string) Finding {
	cmd := NewCommand(raw)

	// An empty command is meaningless — treat it as needing review
	// rather than silently allowing it.
	if cmd.IsEmpty() {
		return Finding{
			CommandOrder: order,
			CommandText:  raw,
			RuleID:       "empty-command",
			Description:  "Command is empty or unparseable",
			Action:       ActionReview,
		}
	}

	for _, rd := range e.rules {
		if rd.matcher(cmd) {
			return Finding{
				CommandOrder: order,
				CommandText:  raw,
				RuleID:       rd.Rule.ID,
				Description:  rd.Rule.Description,
				Action:       rd.Rule.Action,
			}
		}
	}

	// No rule matched: the command is not in any risk category.
	return Finding{
		CommandOrder: order,
		CommandText:  raw,
		RuleID:       "",
		Description:  "No policy rule matched; command considered low-risk",
		Action:       ActionAllow,
	}
}

// verdictForAction maps a per-command Action to a plan-level Verdict.
func verdictForAction(a Action) Verdict {
	switch a {
	case ActionBlock:
		return VerdictBlocked
	case ActionReview:
		return VerdictNeedsReview
	default:
		return VerdictApproved
	}
}

// Summary returns a one-line human-readable description of a decision.
func (d Decision) Summary() string {
	var blocked, review, allowed int
	for _, f := range d.Findings {
		switch f.Action {
		case ActionBlock:
			blocked++
		case ActionReview:
			review++
		default:
			allowed++
		}
	}
	return fmt.Sprintf("%s — %d allowed, %d need review, %d blocked",
		d.Verdict, allowed, review, blocked)
}
