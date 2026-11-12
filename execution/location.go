// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package execution

import (
	"regexp"
	"strconv"

	"witness2test/property"
)

var (
	reachErrorLineRegex = regexp.MustCompile(`witness2test-match: reach_error called at line (\d+)`)
	// The program is compiled from standard input, so its diagnostics and
	// stack frames carry the file name <stdin> (stack frames prefix it with
	// the compilation directory); frames in libc or the harness do not.
	overflowLineRegex = regexp.MustCompile(`(?m)^<stdin>:(\d+):\d+: runtime error: (?:signed integer overflow|[^\n]* cannot be represented in type)`)
	programFrameRegex = regexp.MustCompile(`(?m)^\s*#\d+ 0x[0-9a-f]+ in [^\n]*<stdin>:(\d+)`)
)

// ViolationLine extracts from the test program's stderr the source line at
// which the violation of the given property was observed. The line refers to
// the program as fed to the compiler. It reports false if the line cannot be
// determined, which is always the case for valid-memtrack and
// valid-memcleanup: their reports do not name the violating statement.
func ViolationLine(violated property.Property, stderr string) (int, bool) {
	var regex *regexp.Regexp
	switch violated {
	case property.UnreachCall:
		regex = reachErrorLineRegex
	case property.NoOverflow:
		regex = overflowLineRegex
	case property.ValidFree, property.ValidDeref:
		// The first program frame of the first stack trace: the innermost
		// program statement executing when the error was detected.
		regex = programFrameRegex
	default:
		return 0, false
	}
	m := regex.FindStringSubmatch(stderr)
	if m == nil {
		return 0, false
	}
	line, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return line, true
}
