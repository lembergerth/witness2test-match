// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

// Package instrument rewrites C source so that every witnessed
// __VERIFIER_nondet_X() call site is replaced by a location-stamped injection
// function that returns the witness-supplied values in order. Sites not
// mentioned in the witness are left untouched.
//
// The values of a call site come from function_return waypoints, or else from
// assumption waypoints directly after an assignment of the call, or else from
// branching waypoints whose controlling expression is the call (see
// InstrumentWitness).
//
// The approach is deliberately syntactic: there is no C parser. Only
// single-line call expressions are recognized, calls are distinguished from
// declarations using a small lookahead pattern, and a waypoint that does not
// meet the matching rules exactly is not matched.
//
// The generated definitions are put in front of the program, followed by a
// "#line 1" directive, and linemarkers inside the program are neutralised.
// This way, the compiler and the sanitizers report the physical line numbers
// of the original program, which are the line numbers witnesses refer to.
package instrument

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"witness2test/internal/exitcodes"
	"witness2test/witness"
)

// NondetCallSite describes a real (non-declaration) __VERIFIER_nondet_X() call
// in a C source file. Line and ColumnOfClosingParen are 1-based.
type NondetCallSite struct {
	Line                 int
	ColumnOfClosingParen int
	VariantShortName     string // e.g. "int", "uchar"
	column0              int    // 0-based column of the first char of the call (internal)
	endIdx0              int    // 0-based exclusive end of the call (internal)
}

type witnessedSite struct {
	site   NondetCallSite
	values []string
}

// Patterns mirror test-to-witness/instrument/instrument.go so column accounting
// is identical to what witness producers expect.
// Pattern matches __VERIFIER_nondet_<alphabetic-name>() calls — same shape as
// in test-to-witness. Limiting the suffix to [a-zA-Z]+ makes the regex
// idempotent against our own rewrites of the form
// __VERIFIER_nondet_value_injection_<line>_<col>().
var (
	nondetCallPattern = `__VERIFIER_nondet_[a-zA-Z]+\s*\(\s*(?:void\s*)?\)`
	nondetCallRegex   = regexp.MustCompile(nondetCallPattern)
	nondetDeclRegex   = regexp.MustCompile(`(?:^|[;{}\s])(?:extern\s+)?[a-zA-Z_][a-zA-Z0-9_ *]*\s+` + nondetCallPattern)
	nondetNameRegex   = regexp.MustCompile(`__VERIFIER_nondet_([a-zA-Z]+)`)

	// reach_error() detection mirrors test-to-witness. The declaration filter
	// requires "void reach_error(...)" prefix on the same line so that a
	// definition like `void reach_error(){}` is excluded from instrumentation.
	reachErrorCallPattern = `reach_error\s*\(\s*\)`
	reachErrorCallRegex   = regexp.MustCompile(reachErrorCallPattern)
	reachErrorDeclRegex   = regexp.MustCompile(`(?:^|[;{}\s])(?:extern\s+)?void\s+` + reachErrorCallPattern)
)

// ReachErrorCallSite identifies a real (non-declaration) reach_error() call.
type ReachErrorCallSite struct {
	Line    int
	column0 int
	endIdx0 int
}

// lineEdit is a single right-to-left substitution within one source line.
type lineEdit struct {
	start0, end0 int
	replacement  string
}

// CollectNondetCalls scans the source for __VERIFIER_nondet_X() call sites and
// returns them in source order. Declarations are excluded.
func CollectNondetCalls(source string) []NondetCallSite {
	var sites []NondetCallSite
	for lineIdx, line := range strings.Split(source, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		callIdx := nondetCallRegex.FindAllStringIndex(line, -1)
		if len(callIdx) == 0 {
			continue
		}
		declIdx := nondetDeclRegex.FindAllStringIndex(line, -1)
		for _, ci := range callIdx {
			start, end := ci[0], ci[1]
			if isInside(start, end, declIdx) {
				continue
			}
			match := line[start:end]
			nameMatch := nondetNameRegex.FindStringSubmatch(match)
			if nameMatch == nil {
				continue
			}
			// 0-based exclusive end equals the 1-based column of ')':
			// end-1 is the 0-based index of ')', so end is its 1-based column.
			sites = append(sites, NondetCallSite{
				Line:                 lineIdx + 1,
				ColumnOfClosingParen: end,
				VariantShortName:     nameMatch[1],
				column0:              start,
				endIdx0:              end,
			})
		}
	}
	return sites
}

// CollectReachErrorCalls scans the source for reach_error() call sites (not
// declarations or definitions). Witness2test rewrites these to a wrapper that
// signals the violation reached to the executor via exitcodes.ViolationReached.
func CollectReachErrorCalls(source string) []ReachErrorCallSite {
	var sites []ReachErrorCallSite
	for lineIdx, line := range strings.Split(source, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		callIdx := reachErrorCallRegex.FindAllStringIndex(line, -1)
		if len(callIdx) == 0 {
			continue
		}
		declIdx := reachErrorDeclRegex.FindAllStringIndex(line, -1)
		for _, ci := range callIdx {
			start, end := ci[0], ci[1]
			if isInside(start, end, declIdx) {
				continue
			}
			sites = append(sites, ReachErrorCallSite{
				Line:    lineIdx + 1,
				column0: start,
				endIdx0: end,
			})
		}
	}
	return sites
}

func isInside(start, end int, ranges [][]int) bool {
	for _, r := range ranges {
		if start >= r[0] && end <= r[1] {
			return true
		}
	}
	return false
}

// Options controls InstrumentWitness.
type Options struct {
	// RewriteReachError rewrites reach_error() call sites to a wrapper that
	// reports the physical line of the call (for a call in a macro: of the
	// macro expansion) and exits with exitcodes.ViolationReached.
	// This is only wanted when unreach-call is checked.
	RewriteReachError bool
	// Model is the data model of the program, "ILP32" or "LP64" ("" means
	// LP64). It determines the ranges of the integer types.
	Model string
}

// Result is the outcome of InstrumentWitness.
type Result struct {
	// Source is the complete instrumented program.
	Source string
	// InjectedSites is the number of nondet call sites that received witness
	// values (by any strategy).
	InjectedSites int
	// NondetSites is the number of nondet call sites found in the program.
	NondetSites int
	// Notes explain, in deterministic order, which assumption and branching
	// waypoints of the witness were not turned into input values and why.
	Notes []string
}

// lineDirectiveRegex matches linemarkers ("# 5 "foo.h" 1") and #line
// directives with literal operands.
var lineDirectiveRegex = regexp.MustCompile(`^\s*#\s*(line\s+)?[0-9]+(\s+"[^"]*")?(\s+[0-9]+)*\s*$`)

// lineDirective makes the compiler count the lines of the program from 1
// again, after the generated definitions.
const lineDirective = "#line 1\n"

// InstrumentWitness instruments source with the input values of the witness.
// w must come from witness.ParseWitness, which validates the values that are
// embedded in the generated C code.
//
// Every nondet call site receives its values from exactly one of the
// following sources, in this priority:
//
//  1. function_return waypoints located at the closing parenthesis of the
//     call. Such a waypoint on any other call provides no input value.
//  2. assumption waypoints "x == <literal>" located directly after a plain
//     assignment "x = __VERIFIER_nondet_T();".
//  3. branching waypoints of an if, loop, switch or conditional operator
//     whose controlling expression is the call, its negation, or a comparison
//     of the call with an integer literal.
//
// Assumption and branching waypoints that do not meet the matching rules
// exactly are not used; Result.Notes names them.
func InstrumentWitness(source string, w *witness.Witness, opts Options) (Result, error) {
	model, err := parseDataModel(opts.Model)
	if err != nil {
		return Result{}, err
	}
	if w == nil {
		w = &witness.Witness{}
	}
	// All matching is done on the program as it is compiled. Neutralised
	// lines contain nothing but a directive and keep their line number.
	program := neutraliseLineDirectives(source)
	sites := CollectNondetCalls(program)

	matched, unmatchedNotes := splitFunctionReturns(witness.GroupByLocation(w.Points), sites)
	witnessed, err := matchWitnessToSites(matched, sites)
	if err != nil {
		return Result{}, err
	}
	derived, notes := deriveValues(program, sites, witnessed, w, model)
	notes = append(unmatchedNotes, notes...)
	witnessed = append(witnessed, derived...)
	sortWitnessedSites(witnessed)

	var reachErrorSites []ReachErrorCallSite
	if opts.RewriteReachError {
		reachErrorSites = CollectReachErrorCalls(program)
	}
	return Result{
		Source:        assemble(program, witnessed, reachErrorSites),
		InjectedSites: len(witnessed),
		NondetSites:   len(sites),
		Notes:         notes,
	}, nil
}

// splitFunctionReturns separates the function_return values located at a
// nondet call site from those that are not. A function_return waypoint may
// sit on a call of any function; only those on nondet calls provide input
// values. The others are named in the returned notes, ordered by location.
func splitFunctionReturns(injections map[witness.Location][]string, sites []NondetCallSite) (map[witness.Location][]string, []string) {
	isSite := make(map[witness.Location]bool, len(sites))
	for _, s := range sites {
		isSite[siteLocation(s)] = true
	}
	matched := make(map[witness.Location][]string, len(injections))
	var unmatched []witness.Location
	for loc, values := range injections {
		if isSite[loc] {
			matched[loc] = values
		} else {
			unmatched = append(unmatched, loc)
		}
	}
	sort.Slice(unmatched, func(i, j int) bool {
		if unmatched[i].Line != unmatched[j].Line {
			return unmatched[i].Line < unmatched[j].Line
		}
		return unmatched[i].Column < unmatched[j].Column
	})
	var notes []string
	for _, loc := range unmatched {
		plural := "s"
		if len(injections[loc]) == 1 {
			plural = ""
		}
		notes = append(notes, fmt.Sprintf("function_return at %d:%d (%d value%s) not matched: no __VERIFIER_nondet_X() call ends at the location",
			loc.Line, loc.Column, len(injections[loc]), plural))
	}
	return matched, notes
}

// Instrument rewrites source by replacing witnessed nondet call sites and
// reach_error() call sites, then prepends the generated C definitions
// (per-site injection functions and the reach_error wrapper). Witness
// locations not matching any call site yield an error.
//
// Instrument only knows function_return waypoints. InstrumentWitness also
// derives values from assumption and branching waypoints.
func Instrument(source string, injections map[witness.Location][]string, sites []NondetCallSite, reachErrorSites []ReachErrorCallSite) (string, error) {
	witnessed, err := matchWitnessToSites(injections, sites)
	if err != nil {
		return "", err
	}
	// Neutralising does not move any call site: the affected lines consist
	// of a directive only.
	return assemble(neutraliseLineDirectives(source), witnessed, reachErrorSites), nil
}

// neutraliseLineDirectives replaces every linemarker and #line directive by
// an empty line. The directives would otherwise make the compiler report
// presumed line numbers instead of the physical ones.
func neutraliseLineDirectives(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		if lineDirectiveRegex.MatchString(line) {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// assemble applies the rewrites to program, whose line directives are
// already neutralised, and puts the generated definitions in front of it.
// Without definitions, the result is the program itself.
//
// Every rewrite comes with a definition (an injection function or the
// reach_error wrapper), so a rewritten program always follows a "#line 1".
// The __LINE__ of reachErrorReplacement relies on this.
func assemble(program string, witnessed []witnessedSite, reachErrorSites []ReachErrorCallSite) string {
	rewritten := rewriteSource(program, witnessed, reachErrorSites)
	defs := buildDefinitions(witnessed, len(reachErrorSites) > 0)
	if defs == "" {
		return rewritten
	}
	return defs + lineDirective + rewritten
}

// matchWitnessToSites pairs each witnessed location with its source call site,
// erroring out if any witness location does not correspond to a call.
// The returned slice is sorted by (line, column) so generated output is byte-stable.
func matchWitnessToSites(injections map[witness.Location][]string, sites []NondetCallSite) ([]witnessedSite, error) {
	siteByLoc := make(map[witness.Location]NondetCallSite, len(sites))
	for _, s := range sites {
		siteByLoc[witness.Location{Line: s.Line, Column: s.ColumnOfClosingParen}] = s
	}

	witnessed := make([]witnessedSite, 0, len(injections))
	var unmatched []witness.Location
	for loc, values := range injections {
		s, ok := siteByLoc[loc]
		if !ok {
			unmatched = append(unmatched, loc)
			continue
		}
		witnessed = append(witnessed, witnessedSite{site: s, values: values})
	}
	if len(unmatched) > 0 {
		return nil, unmatchedLocationsError(unmatched)
	}
	sortWitnessedSites(witnessed)
	return witnessed, nil
}

func sortWitnessedSites(witnessed []witnessedSite) {
	sort.Slice(witnessed, func(i, j int) bool {
		if witnessed[i].site.Line != witnessed[j].site.Line {
			return witnessed[i].site.Line < witnessed[j].site.Line
		}
		return witnessed[i].site.ColumnOfClosingParen < witnessed[j].site.ColumnOfClosingParen
	})
}

func unmatchedLocationsError(unmatched []witness.Location) error {
	sort.Slice(unmatched, func(i, j int) bool {
		if unmatched[i].Line != unmatched[j].Line {
			return unmatched[i].Line < unmatched[j].Line
		}
		return unmatched[i].Column < unmatched[j].Column
	})
	locs := make([]string, len(unmatched))
	for i, l := range unmatched {
		locs[i] = fmt.Sprintf("%d:%d", l.Line, l.Column)
	}
	return fmt.Errorf("witness location(s) do not match any __VERIFIER_nondet_X() call site in the source: %s", strings.Join(locs, ", "))
}

// reachErrorReplacement replaces a reach_error() call. The line is not the
// line of the call in the source text: if the call is in the replacement list
// of a macro, the violation happens where the macro is expanded, and that is
// the line __LINE__ evaluates to. __LINE__ is a physical line of the program
// because assemble puts a "#line 1" in front of every program that contains a
// replacement, and because the program's own line directives are neutralised.
const reachErrorReplacement = "__VERIFIER_w2t_reach_error(__LINE__)"

// rewriteSource applies the witnessed-nondet rewrites and the reach_error
// rewrites to source. Edits within a line are applied right-to-left so earlier
// offsets stay valid.
func rewriteSource(source string, witnessed []witnessedSite, reachErrorSites []ReachErrorCallSite) string {
	edits := make(map[int][]lineEdit)
	for _, ws := range witnessed {
		s := ws.site
		edits[s.Line] = append(edits[s.Line], lineEdit{
			start0:      s.column0,
			end0:        s.endIdx0,
			replacement: fmt.Sprintf("__VERIFIER_nondet_value_injection_%d_%d()", s.Line, s.ColumnOfClosingParen),
		})
	}
	for _, r := range reachErrorSites {
		edits[r.Line] = append(edits[r.Line], lineEdit{
			start0:      r.column0,
			end0:        r.endIdx0,
			replacement: reachErrorReplacement,
		})
	}
	if len(edits) == 0 {
		return source
	}

	lines := strings.Split(source, "\n")
	for lineNum, lineEdits := range edits {
		sort.Slice(lineEdits, func(i, j int) bool { return lineEdits[i].start0 > lineEdits[j].start0 })
		line := lines[lineNum-1]
		for _, e := range lineEdits {
			line = line[:e.start0] + e.replacement + line[e.end0:]
		}
		lines[lineNum-1] = line
	}
	return strings.Join(lines, "\n")
}

// buildDefinitions returns the generated C definitions, or "" if there is
// nothing to define.
func buildDefinitions(witnessed []witnessedSite, includeReachError bool) string {
	if len(witnessed) == 0 && !includeReachError {
		return ""
	}
	var b strings.Builder
	b.WriteString("/* witness2test-match: generated definitions */\n")
	b.WriteString("extern void _Exit(int);\n")
	b.WriteString(syscallDeclarations)
	if includeReachError {
		b.WriteString(generateReachErrorWrapper())
	}
	for _, ws := range witnessed {
		b.WriteString(generateInjectionFunction(ws.site, ws.values))
	}
	b.WriteString("/* end of generated definitions */\n")
	return b.String()
}

// syscallDeclarations declares what the generated code needs to write
// messages with the write system call. It does not call the write() function:
// SV-COMP programs (busybox, coreutils) define their own write() stub. The
// number of the system call is taken from the predefined macros of the
// compiler because the definitions must not include headers in front of the
// program.
const syscallDeclarations = "extern long syscall(long, ...);\n" +
	"#if defined(__x86_64__)\n" +
	"#define __W2T_SYS_WRITE 1\n" +
	"#elif defined(__i386__)\n" +
	"#define __W2T_SYS_WRITE 4\n" +
	"#else\n" +
	"#error \"witness2test-match: unsupported architecture\"\n" +
	"#endif\n"

// generateReachErrorWrapper returns the definition of the function that
// replaces reach_error(). It reports the line of the call (for a call in a
// macro: the line of the macro expansion) on stderr, so that
// the line can be compared with the target waypoint of the witness, and exits
// with exitcodes.ViolationReached. The message is written with a single
// write system call and the number is formatted by hand: stdio may not be
// usable in the program under test.
func generateReachErrorWrapper() string {
	return fmt.Sprintf(
		"void __VERIFIER_w2t_reach_error(int line) {\n"+
			"  static const char prefix[] = \"witness2test-match: reach_error called at line \";\n"+
			"  char msg[sizeof(prefix) + 16];\n"+
			"  char digits[12];\n"+
			"  unsigned value = line > 0 ? (unsigned)line : 0u;\n"+
			"  unsigned ndigits = 0;\n"+
			"  unsigned len = 0;\n"+
			"  while (len < sizeof(prefix) - 1) { msg[len] = prefix[len]; len++; }\n"+
			"  do { digits[ndigits++] = (char)('0' + value %% 10u); value /= 10u; } while (value != 0u);\n"+
			"  while (ndigits > 0) { msg[len++] = digits[--ndigits]; }\n"+
			"  msg[len++] = '\\n';\n"+
			"  syscall(__W2T_SYS_WRITE, 2, msg, len);\n"+
			"  _Exit(%d);\n"+
			"}\n",
		exitcodes.ViolationReached,
	)
}

func generateInjectionFunction(s NondetCallSite, values []string) string {
	returnType := actualFunctionTypeFromShortName(s.VariantShortName)
	funcName := fmt.Sprintf("__VERIFIER_nondet_value_injection_%d_%d", s.Line, s.ColumnOfClosingParen)
	msg := fmt.Sprintf("witness2test-match: nondet overflow at %d:%d\\n", s.Line, s.ColumnOfClosingParen)
	return fmt.Sprintf(
		"%[1]s %[2]s(void) {\n"+
			"  static const %[1]s values[] = { %[3]s };\n"+
			"  static unsigned idx = 0;\n"+
			"  if (idx >= sizeof(values)/sizeof(values[0])) {\n"+
			"    const char msg[] = \"%[4]s\";\n"+
			"    syscall(__W2T_SYS_WRITE, 2, msg, sizeof(msg)-1);\n"+
			"    _Exit(%[5]d);\n"+
			"  }\n"+
			"  return values[idx++];\n"+
			"}\n",
		returnType, funcName, strings.Join(values, ", "), msg, exitcodes.WitnessInconsistent,
	)
}

// actualFunctionTypeFromShortName mirrors the same mapping used by
// test-to-witness so column accounting and type matching stay consistent.
func actualFunctionTypeFromShortName(shortName string) string {
	typeMap := map[string]string{
		"uint":          "unsigned int",
		"uchar":         "unsigned char",
		"unsigned_char": "unsigned char",
		"ushort":        "unsigned short",
		"ulong":         "unsigned long",
		"ulonglong":     "unsigned long long",
		"longlong":      "long long",
		"uint128":       "__uint128_t",
		"int128":        "__int128_t",
		"bool":          "_Bool",
		"u8":            "unsigned char",
		"u16":           "unsigned short",
		"u32":           "unsigned int",
		"U32":           "unsigned int",
		"size_t":        "unsigned int",
		"pointer":       "void *",
		"unsigned":      "unsigned int",
	}
	if t, ok := typeMap[shortName]; ok {
		return t
	}
	return shortName
}
