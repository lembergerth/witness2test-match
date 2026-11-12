// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package execution

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"witness2test/internal/exitcodes"
	"witness2test/property"
)

// memcleanupMarker is the line the embedded harness prints when the program
// terminates with live allocations (see harness.c.template).
const memcleanupMarker = "witness2test-match: memory not deallocated at termination"

// reachErrorMarker starts the line that both the generated reach_error
// wrapper and the harness's reach_error print before exiting.
const reachErrorMarker = "witness2test-match: reach_error called"

// wrappedFunctions are redirected to the wrappers of the harness when
// valid-memcleanup is checked.
var wrappedFunctions = []string{
	"malloc", "calloc", "realloc", "reallocarray", "aligned_alloc", "posix_memalign", "strdup", "free",
	// Ways to terminate the program that skip the exit handlers.
	"abort", "_Exit", "_exit", "__assert_fail",
}

func checksMemory(properties []property.Property) bool {
	return property.Contains(properties, property.ValidFree) ||
		property.Contains(properties, property.ValidDeref) ||
		property.Contains(properties, property.ValidMemtrack)
}

// propertyCompilerArgs returns the gcc arguments that make violations of the
// given properties observable at run time.
func propertyCompilerArgs(properties []property.Property) []string {
	var args []string
	sanitized := false
	if property.Contains(properties, property.NoOverflow) {
		sanitized = true
		args = append(args,
			// Exactly the operations SV-COMP's no-overflow covers: + - * unary-
			// and / (signed-integer-overflow) and << (shift-base). Conversions
			// (float-cast-overflow) are deliberately not checked.
			"-fsanitize=signed-integer-overflow,shift-base",
			// abs(INT_MIN) and friends are not violations of no-overflow; as
			// builtins gcc would expand them to a checked negation.
			"-fno-builtin-abs", "-fno-builtin-labs", "-fno-builtin-llabs", "-fno-builtin-imaxabs",
		)
	}
	if checksMemory(properties) {
		sanitized = true
		args = append(args, "-fsanitize=address", "-fno-omit-frame-pointer")
	}
	if sanitized {
		// -g lets the sanitizers report source lines.
		args = append(args, "-fno-sanitize-recover=all", "-g")
	}
	if property.Contains(properties, property.ValidMemtrack) {
		// Enables the correction for pointers to the end of a block.
		args = append(args, "-DW2T_CHECK_MEMTRACK")
	}
	if property.Contains(properties, property.ValidMemcleanup) {
		wraps := make([]string, 0, len(wrappedFunctions))
		for _, function := range wrappedFunctions {
			wraps = append(wraps, "--wrap="+function)
		}
		args = append(args, "-DW2T_CHECK_MEMCLEANUP", "-Wl,"+strings.Join(wraps, ","))
	}
	return args
}

// sanitizerEnvironment returns the environment variables that configure the
// sanitizer runtimes of the test program.
func sanitizerEnvironment(properties []property.Property) []string {
	exit := fmt.Sprintf("exitcode=%d", exitcodes.SanitizerReport)
	leaks := "detect_leaks=0"
	if property.Contains(properties, property.ValidMemtrack) {
		leaks = "detect_leaks=1"
	}
	return []string{
		"ASAN_OPTIONS=" + exit + ":" + leaks + ":detect_stack_use_after_return=1:abort_on_error=0",
		// use_unaligned: a pointer stored at an unaligned address (packed
		// struct) still references its block.
		"LSAN_OPTIONS=" + exit + ":use_unaligned=1",
		"UBSAN_OPTIONS=" + exit + ":halt_on_error=1:print_stacktrace=0",
	}
}

type classification struct {
	status   VerdictStatus
	violated property.Property
	detail   string
}

var (
	// "cannot be represented in type" is what the undefined-behavior sanitizer
	// prints for exactly the cases whose mathematical result does not fit the
	// signed result type. Other shift reports (negative base, exponent too
	// large) are undefined behavior, but not overflows in the SV-COMP sense.
	overflowReportRegex = regexp.MustCompile(`runtime error: (signed integer overflow|[^\n]* cannot be represented in type)`)
	asanSummaryRegex    = regexp.MustCompile(`SUMMARY: AddressSanitizer: ([A-Za-z-]+)`)
)

// asanKinds maps the error kind of an AddressSanitizer summary to the
// memory-safety subproperty it violates. Kinds that are not listed (e.g.
// stack-overflow from deep recursion, memcpy-param-overlap) violate none.
var asanKinds = map[string]property.Property{
	"double-free":            property.ValidFree,
	"bad-free":               property.ValidFree,
	"alloc-dealloc-mismatch": property.ValidFree,

	"heap-use-after-free":           property.ValidDeref,
	"heap-buffer-overflow":          property.ValidDeref,
	"stack-buffer-overflow":         property.ValidDeref,
	"stack-buffer-underflow":        property.ValidDeref,
	"global-buffer-overflow":        property.ValidDeref,
	"dynamic-stack-buffer-overflow": property.ValidDeref,
	"stack-use-after-return":        property.ValidDeref,
	"stack-use-after-scope":         property.ValidDeref,
	"SEGV":                          property.ValidDeref,
}

var remainderReportRegex = regexp.MustCompile(`(?m)^<stdin>:(\d+):(\d+): runtime error: division of [^\n]* cannot be represented in type`)

// generatedCodeEnd is the line that separates the generated definitions from
// the program in the compiled source; lines in reports count from there.
const generatedCodeEnd = "\n#line 1\n"

// OverflowReportIsForRemainder reports whether the first overflow report in
// stderr is about a remainder operation (INT_MIN % -1) in the compiled
// source. The sanitizer words that report like the one for INT_MIN / -1, but
// the remainder is not among the operations of no-overflow, and its result is
// representable. The two are told apart by the operator at the reported
// source position.
func OverflowReportIsForRemainder(stderr, source string) bool {
	first := overflowReportRegex.FindStringIndex(stderr)
	if first == nil {
		return false
	}
	lineStart := strings.LastIndexByte(stderr[:first[0]], '\n') + 1
	lineEnd := len(stderr)
	if i := strings.IndexByte(stderr[lineStart:], '\n'); i >= 0 {
		lineEnd = lineStart + i
	}
	m := remainderReportRegex.FindStringSubmatch(stderr[lineStart:lineEnd])
	if m == nil {
		return false
	}
	line, _ := strconv.Atoi(m[1])
	column, _ := strconv.Atoi(m[2])
	if i := strings.Index(source, generatedCodeEnd); i >= 0 {
		source = source[i+len(generatedCodeEnd):]
	}
	lines := strings.Split(source, "\n")
	if line < 1 || line > len(lines) || column < 1 || column > len(lines[line-1]) {
		return false
	}
	return lines[line-1][column-1] == '%'
}

// observedViolation determines which property, if any, the finished test
// program violated, independent of which properties are being checked.
func observedViolation(exitCode int, stderr string) property.Property {
	switch exitCode {
	case exitcodes.ViolationReached:
		// As for the other properties, the exit code alone is not enough:
		// the program may use it for its own purposes.
		if strings.Contains(stderr, reachErrorMarker) {
			return property.UnreachCall
		}
	case exitcodes.MemcleanupViolation:
		if strings.Contains(stderr, memcleanupMarker) {
			return property.ValidMemcleanup
		}
	case exitcodes.SanitizerReport:
		if overflowReportRegex.MatchString(stderr) {
			return property.NoOverflow
		}
		if strings.Contains(stderr, "ERROR: LeakSanitizer: detected memory leaks") {
			return property.ValidMemtrack
		}
		if m := asanSummaryRegex.FindStringSubmatch(stderr); m != nil {
			return asanKinds[m[1]]
		}
	}
	return ""
}

// classify turns the outcome of a test execution into a verdict status. A
// violation is confirmed only if it violates one of the checked properties.
func classify(exitCode int, stderr string, properties []property.Property) classification {
	if exitCode == exitcodes.WitnessInconsistent {
		return classification{status: Inconsistent}
	}
	violated := observedViolation(exitCode, stderr)
	if violated == "" {
		return classification{status: NotConfirmed}
	}
	if !property.Contains(properties, violated) {
		return classification{
			status: NotConfirmed,
			detail: fmt.Sprintf("execution violated %s, which is not among the checked properties", violated),
		}
	}
	return classification{status: Confirmed, violated: violated}
}
