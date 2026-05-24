package policy

import "strings"

// Command is a parsed view of a single shell command. Policy rules
// query it through high-level methods instead of touching raw strings.
//
// TAPPA 1: parsing is token-based. It splits the command into words
// and inspects them. This is solid for real-world commands but is not
// a full grammar parser.
// TAPPA 2: the internals will be replaced with the mvdan/sh AST parser.
// The method signatures below are the stable contract — rules depend
// on these, not on how parsing works underneath.
type Command struct {
	raw    string   // the original command string, untouched
	tokens []string // whitespace-split tokens
	binary string   // the executable being invoked (first real token)
	args   []string // everything after the binary
}

// NewCommand parses a raw shell command string into a Command.
func NewCommand(raw string) *Command {
	trimmed := strings.TrimSpace(raw)
	tokens := strings.Fields(trimmed)

	c := &Command{
		raw:    trimmed,
		tokens: tokens,
	}
	if len(tokens) > 0 {
		c.binary = baseName(tokens[0])
		c.args = tokens[1:]
	}
	return c
}

// Raw returns the original command string.
func (c *Command) Raw() string {
	return c.raw
}

// IsEmpty reports whether the command has no content.
func (c *Command) IsEmpty() bool {
	return len(c.tokens) == 0
}

// HasBinary reports whether the command's executable is exactly name.
// The path is stripped, so "/usr/bin/rm" matches HasBinary("rm").
func (c *Command) HasBinary(name string) bool {
	return c.binary == name
}

// HasBinaryPrefix reports whether the executable name starts with prefix.
// Useful for families like mkfs.ext4, mkfs.xfs.
func (c *Command) HasBinaryPrefix(prefix string) bool {
	return strings.HasPrefix(c.binary, prefix)
}

// HasArg reports whether any argument is exactly value.
func (c *Command) HasArg(value string) bool {
	for _, a := range c.args {
		if a == value {
			return true
		}
	}
	return false
}

// HasArgContaining reports whether any token contains the given substring.
func (c *Command) HasArgContaining(substr string) bool {
	for _, t := range c.tokens {
		if strings.Contains(t, substr) {
			return true
		}
	}
	return false
}

// HasFlagLike reports whether any flag carries the given letter.
// It handles both grouped short flags ("-rf" contains "r" and "f")
// and long flags ("--recursive" contains "recursive").
func (c *Command) HasFlagLike(letter string) bool {
	for _, a := range c.args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		flag := strings.TrimLeft(a, "-")
		// Long flag: exact word match.
		if flag == longFlagFor(letter) {
			return true
		}
		// Short grouped flags: the letter appears in the group.
		if len(letter) == 1 && strings.Contains(flag, letter) {
			return true
		}
	}
	return false
}

// WritesUnderPath reports whether the command appears to target a path
// under the given directory prefix (e.g. "/etc/"). Conservative: it
// flags any token referencing that path, since in a safety engine a
// false "review" is acceptable but a missed one is not.
func (c *Command) WritesUnderPath(prefix string) bool {
	for _, t := range c.tokens {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

// RawContains reports whether the raw command string contains substr.
// Used for signature patterns like fork bombs that defeat tokenization.
func (c *Command) RawContains(substr string) bool {
	return strings.Contains(stripWhitespace(c.raw), stripWhitespace(substr))
}

// --- helpers ---

// baseName strips the directory part of a path: "/usr/bin/rm" -> "rm".
func baseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// longFlagFor maps a short flag letter to its common long-flag spelling.
func longFlagFor(letter string) string {
	switch letter {
	case "r":
		return "recursive"
	case "f":
		return "force"
	case "R":
		return "recursive"
	default:
		return letter
	}
}

// stripWhitespace removes all spaces and tabs, so signature matching
// is not defeated by inserting blanks.
func stripWhitespace(s string) string {
	return strings.NewReplacer(" ", "", "\t", "").Replace(s)
}
