// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

// Package instrument rewrites C source so that every witnessed
// __VERIFIER_nondet_X() call site is replaced by a location-stamped injection
// function that returns the witness-supplied values in order. Sites not
// mentioned in the witness are left untouched.
//
// The regex-based approach mirrors test-to-witness/instrument: it is
// deliberately syntactic, recognizes only single-line call expressions, and
// distinguishes calls from declarations using a small lookahead pattern.
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

// Instrument rewrites source by replacing witnessed nondet call sites and
// reach_error() call sites, then prepends the generated C definitions
// (per-site injection functions and the reach_error wrapper). Witness
// locations not matching any call site yield an error.
func Instrument(source string, injections map[witness.Location][]string, sites []NondetCallSite, reachErrorSites []ReachErrorCallSite) (string, error) {
	witnessed, err := matchWitnessToSites(injections, sites)
	if err != nil {
		return "", err
	}
	rewritten := rewriteSource(source, witnessed, reachErrorSites)
	defs := buildDefinitions(witnessed, len(reachErrorSites) > 0)
	return defs + rewritten, nil
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
	sort.Slice(witnessed, func(i, j int) bool {
		if witnessed[i].site.Line != witnessed[j].site.Line {
			return witnessed[i].site.Line < witnessed[j].site.Line
		}
		return witnessed[i].site.ColumnOfClosingParen < witnessed[j].site.ColumnOfClosingParen
	})
	return witnessed, nil
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
			replacement: "__VERIFIER_w2t_reach_error()",
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

func buildDefinitions(witnessed []witnessedSite, includeReachError bool) string {
	if len(witnessed) == 0 && !includeReachError {
		return ""
	}
	var b strings.Builder
	b.WriteString("/* witness2test: generated definitions */\n")
	b.WriteString("extern void _Exit(int);\n")
	b.WriteString("extern long write(int, const void *, unsigned long);\n")
	if includeReachError {
		b.WriteString(fmt.Sprintf("void __VERIFIER_w2t_reach_error(void) { _Exit(%d); }\n", exitcodes.ViolationReached))
	}
	for _, ws := range witnessed {
		b.WriteString(generateInjectionFunction(ws.site, ws.values))
	}
	b.WriteString("/* end of generated definitions */\n\n")
	return b.String()
}

func generateInjectionFunction(s NondetCallSite, values []string) string {
	returnType := actualFunctionTypeFromShortName(s.VariantShortName)
	funcName := fmt.Sprintf("__VERIFIER_nondet_value_injection_%d_%d", s.Line, s.ColumnOfClosingParen)
	msg := fmt.Sprintf("witness2test: nondet overflow at %d:%d\\n", s.Line, s.ColumnOfClosingParen)
	return fmt.Sprintf(
		"%[1]s %[2]s(void) {\n"+
			"  static const %[1]s values[] = { %[3]s };\n"+
			"  static unsigned idx = 0;\n"+
			"  if (idx >= sizeof(values)/sizeof(values[0])) {\n"+
			"    const char msg[] = \"%[4]s\";\n"+
			"    write(2, msg, sizeof(msg)-1);\n"+
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
