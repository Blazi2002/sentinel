package policy

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command is a parsed view of a shell command, backed by a real shell
// grammar parser (mvdan/sh). It walks the syntax tree and extracts every
// concrete command invocation — including ones nested inside eval,
// sh -c, command substitutions, pipelines and && / || chains.
//
// Policy rules query this type through high-level methods and never
// touch the AST directly: the method set is the stable contract.
type Command struct {
	raw   string       // the original command string, untouched
	calls []invocation // every concrete invocation found in the tree
}

// invocation is one concrete command found in the parsed tree,
// e.g. "rm" with args ["-rf", "/data"].
type invocation struct {
	binary string   // executable name, path stripped
	args   []string // arguments following the binary
	words  []string // binary + args together, for substring scans
}

// NewCommand parses a raw shell command string into a Command.
// If parsing fails (malformed input), the command is still represented
// with a single best-effort invocation so rules can act conservatively.
func NewCommand(raw string) *Command {
	trimmed := strings.TrimSpace(raw)
	c := &Command{raw: trimmed}

	if trimmed == "" {
		return c
	}

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(trimmed), "")
	if err != nil {
		// Unparseable: fall back to naive tokenization so the command
		// is never invisible to the rule set.
		c.calls = append(c.calls, fallbackInvocation(trimmed))
		return c
	}

	// Walk the syntax tree and collect every CallExpr (a concrete
	// command invocation). For commands that re-execute a string as
	// shell code (eval, sh -c), recursively parse that string too.
	var pending []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		inv := invocationFromCall(call)
		c.calls = append(c.calls, inv)
		pending = append(pending, nestedShellStrings(inv)...)
		return true
	})

	// Recursively analyze shell code hidden inside eval / sh -c.
	for _, code := range pending {
		nested := NewCommand(code)
		c.calls = append(c.calls, nested.calls...)
	}

	// If the walk found nothing usable, fall back so rules still see it.
	if len(c.calls) == 0 {
		c.calls = append(c.calls, fallbackInvocation(trimmed))
	}
	return c
}

// invocationFromCall turns one AST CallExpr into an invocation.
func invocationFromCall(call *syntax.CallExpr) invocation {
	var words []string
	for _, word := range call.Args {
		words = append(words, wordText(word))
	}

	inv := invocation{words: words}
	if len(words) > 0 {
		inv.binary = baseName(words[0])
		inv.args = words[1:]
	}
	return inv
}

// nestedShellStrings returns argument strings that a command would
// itself execute as shell code: the argument of `eval` and the string
// after `sh -c` / `bash -c`. These need to be parsed recursively.
func nestedShellStrings(inv invocation) []string {
	var nested []string
	switch inv.binary {
	case "eval":
		// every argument of eval is treated as shell code
		nested = append(nested, inv.args...)
	case "sh", "bash", "dash", "ash":
		// the token right after -c is shell code
		for i, a := range inv.args {
			if a == "-c" && i+1 < len(inv.args) {
				nested = append(nested, inv.args[i+1])
			}
		}
	}
	return nested
}

// wordText flattens an AST word into plain text. Quotes are removed,
// so "rm" and rm and 'rm' all flatten to rm. Expansions like $(...)
// are kept as literal text so substring rules can still catch them.
func wordText(word *syntax.Word) string {
	var b strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dqPart := range p.Parts {
				if lit, ok := dqPart.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				}
			}
		}
	}
	return b.String()
}

// fallbackInvocation builds an invocation by naive splitting,
// used only when the grammar parser cannot handle the input.
func fallbackInvocation(raw string) invocation {
	tokens := strings.Fields(raw)
	inv := invocation{words: tokens}
	if len(tokens) > 0 {
		inv.binary = baseName(tokens[0])
		inv.args = tokens[1:]
	}
	return inv
}

// --- query methods: the stable contract used by policy rules ---

// Raw returns the original command string.
func (c *Command) Raw() string {
	return c.raw
}

// IsEmpty reports whether the command has no content.
func (c *Command) IsEmpty() bool {
	return len(c.calls) == 0
}

// HasBinary reports whether ANY invocation in the command (including
// nested ones) runs exactly the given executable.
func (c *Command) HasBinary(name string) bool {
	for _, inv := range c.calls {
		if inv.binary == name {
			return true
		}
	}
	return false
}

// HasBinaryPrefix reports whether any invocation's executable name
// starts with prefix (e.g. the mkfs.* family).
func (c *Command) HasBinaryPrefix(prefix string) bool {
	for _, inv := range c.calls {
		if strings.HasPrefix(inv.binary, prefix) {
			return true
		}
	}
	return false
}

// HasArg reports whether any invocation has an argument exactly equal
// to value.
func (c *Command) HasArg(value string) bool {
	for _, inv := range c.calls {
		for _, a := range inv.args {
			if a == value {
				return true
			}
		}
	}
	return false
}

// HasArgContaining reports whether any word of any invocation contains
// the given substring.
func (c *Command) HasArgContaining(substr string) bool {
	for _, inv := range c.calls {
		for _, w := range inv.words {
			if strings.Contains(w, substr) {
				return true
			}
		}
	}
	return false
}

// HasFlagLike reports whether any invocation carries a flag with the
// given letter, handling grouped short flags ("-rf") and long flags
// ("--recursive").
func (c *Command) HasFlagLike(letter string) bool {
	for _, inv := range c.calls {
		for _, a := range inv.args {
			if !strings.HasPrefix(a, "-") {
				continue
			}
			flag := strings.TrimLeft(a, "-")
			if flag == longFlagFor(letter) {
				return true
			}
			if len(letter) == 1 && strings.Contains(flag, letter) {
				return true
			}
		}
	}
	return false
}

// WritesUnderPath reports whether any invocation references a path
// under the given directory prefix. Conservative by design: in a
// safety engine a false "review" is acceptable, a missed one is not.
func (c *Command) WritesUnderPath(prefix string) bool {
	for _, inv := range c.calls {
		for _, w := range inv.words {
			if strings.HasPrefix(w, prefix) {
				return true
			}
		}
	}
	return false
}

// RawContains reports whether the raw command string contains substr,
// ignoring whitespace. Used for signature patterns like fork bombs.
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
	case "r", "R":
		return "recursive"
	case "f":
		return "force"
	default:
		return letter
	}
}

// stripWhitespace removes spaces and tabs so signature matching is not
// defeated by inserting blanks.
func stripWhitespace(s string) string {
	return strings.NewReplacer(" ", "", "\t", "").Replace(s)
}
