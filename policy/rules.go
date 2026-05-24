// Package policy is the deterministic validation engine of Sentinel.
// It inspects remediation commands produced by the reasoning hub and
// decides whether each one may run, must be reviewed, or is forbidden.
//
// This package contains NO probabilistic logic: given the same command
// it always returns the same verdict. It is the safety moat between an
// LLM's output and a root shell.
package policy

// Action is what the engine decides to do with a single command.
type Action int

const (
	// ActionAllow: the command is low-risk and reversible.
	ActionAllow Action = iota
	// ActionReview: the command is legitimate but high-impact;
	// a human operator must approve it before it runs.
	ActionReview
	// ActionBlock: the command is destructive or forbidden and
	// must never run, not even with operator approval.
	ActionBlock
)

// String renders an Action for logs and decisions.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionReview:
		return "review"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Rule is a single named policy rule.
// If Match returns true for a command, the rule's Action applies.
type Rule struct {
	ID          string // stable identifier, e.g. "no-rm-rf"
	Description string // human-readable explanation
	Action      Action // what to do when this rule matches
}

// ruleDefinition pairs a Rule with the matcher that triggers it.
// matcher receives the parsed command and reports whether the rule applies.
type ruleDefinition struct {
	Rule    Rule
	matcher func(cmd *Command) bool
}

// The rule set is evaluated in order. The FIRST matching rule wins,
// so rules are ordered most-dangerous first: a command that matches
// both a block rule and a review rule is blocked.
var ruleSet = []ruleDefinition{
	// ---- BLOCK: destructive or forbidden, never executed ----
	{
		Rule: Rule{
			ID:          "no-recursive-force-delete",
			Description: "Recursive forced deletion is destructive and irreversible",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("rm") && c.HasFlagLike("r") && c.HasFlagLike("f")
		},
	},
	{
		Rule: Rule{
			ID:          "no-filesystem-format",
			Description: "Filesystem formatting destroys all data on a device",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return c.HasBinaryPrefix("mkfs") || c.HasBinary("mke2fs")
		},
	},
	{
		Rule: Rule{
			ID:          "no-raw-disk-write",
			Description: "Raw writes to block devices can destroy a disk",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("dd") && c.HasArgContaining("of=/dev/")
		},
	},
	{
		Rule: Rule{
			ID:          "no-outbound-network-fetch",
			Description: "Fetching and running external content bypasses air-gap guarantees",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("curl") || c.HasBinary("wget")
		},
	},
	{
		Rule: Rule{
			ID:          "no-disk-wipe",
			Description: "Disk-wiping tools destroy data irreversibly",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("shred") || c.HasBinary("wipefs")
		},
	},
	{
		Rule: Rule{
			ID:          "no-fork-bomb",
			Description: "Fork bombs exhaust system resources and crash the host",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return c.RawContains(":(){:|:&};:") || c.RawContains(":|:&")
		},
	},
	{
		Rule: Rule{
			ID:          "no-ownership-recursive-root",
			Description: "Recursive ownership changes on / break the entire system",
			Action:      ActionBlock,
		},
		matcher: func(c *Command) bool {
			return (c.HasBinary("chown") || c.HasBinary("chmod")) &&
				c.HasFlagLike("R") && c.HasArgContaining(" /")
		},
	},

	// ---- REVIEW: legitimate but high-impact, needs human approval ----
	{
		Rule: Rule{
			ID:          "review-firewall-change",
			Description: "Firewall changes can cut off network access to the host",
			Action:      ActionReview,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("iptables") || c.HasBinary("nft") ||
				c.HasBinary("firewall-cmd") || c.HasBinary("ufw")
		},
	},
	{
		Rule: Rule{
			ID:          "review-process-kill",
			Description: "Killing processes can interrupt running workloads",
			Action:      ActionReview,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("kill") || c.HasBinary("killall") || c.HasBinary("pkill")
		},
	},
	{
		Rule: Rule{
			ID:          "review-system-config-edit",
			Description: "Edits to system or kernel paths affect host behavior",
			Action:      ActionReview,
		},
		matcher: func(c *Command) bool {
			return c.WritesUnderPath("/etc/") ||
				c.WritesUnderPath("/proc/") ||
				c.WritesUnderPath("/sys/") ||
				c.WritesUnderPath("/boot/")
		},
	},
	{
		Rule: Rule{
			ID:          "review-package-management",
			Description: "Installing or removing packages changes the system baseline",
			Action:      ActionReview,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("dnf") || c.HasBinary("yum") ||
				c.HasBinary("apt") || c.HasBinary("apt-get") || c.HasBinary("rpm")
		},
	},
	{
		Rule: Rule{
			ID:          "review-service-stop-or-disable",
			Description: "Stopping or disabling a service may take a workload offline",
			Action:      ActionReview,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("systemctl") &&
				(c.HasArg("stop") || c.HasArg("disable") || c.HasArg("mask"))
		},
	},
	{
		Rule: Rule{
			ID:          "review-reboot-or-poweroff",
			Description: "Rebooting or powering off interrupts all services on the host",
			Action:      ActionReview,
		},
		matcher: func(c *Command) bool {
			return c.HasBinary("reboot") || c.HasBinary("poweroff") ||
				c.HasBinary("shutdown") || c.HasBinary("halt")
		},
	},
}
