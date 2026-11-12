// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

// Package property models the SV-COMP properties witness2test-match knows and
// parses them from property files and from witness specifications.
package property

import (
	"fmt"
	"regexp"
	"strings"
)

// Property names one SV-COMP property (or memory-safety subproperty).
type Property string

const (
	UnreachCall     Property = "unreach-call"
	ValidFree       Property = "valid-memsafety(valid-free)"
	ValidDeref      Property = "valid-memsafety(valid-deref)"
	ValidMemtrack   Property = "valid-memsafety(valid-memtrack)"
	NoOverflow      Property = "no-overflow"
	NoDataRace      Property = "no-data-race"
	ValidMemcleanup Property = "valid-memcleanup"
)

var formulas = []struct {
	property Property
	formula  string
}{
	{UnreachCall, `G\s+!\s+call\s*\(\s*reach_error\s*\(\s*\)\s*\)`},
	{ValidFree, `G\s+valid-free`},
	{ValidDeref, `G\s+valid-deref`},
	{ValidMemtrack, `G\s+valid-memtrack`},
	{NoOverflow, `G\s+!\s+overflow`},
	{NoDataRace, `G\s+!\s+data-race`},
	{ValidMemcleanup, `G\s+valid-memcleanup`},
}

type pattern struct {
	property Property
	check    *regexp.Regexp // full CHECK( init(main()), LTL(<formula>) ) expression
	bare     *regexp.Regexp // the LTL formula on its own
}

var patterns = buildPatterns()

func buildPatterns() []pattern {
	result := make([]pattern, 0, len(formulas))
	for _, f := range formulas {
		result = append(result, pattern{
			property: f.property,
			check:    regexp.MustCompile(`^\s*CHECK\s*\(\s*init\s*\(\s*main\s*\(\s*\)\s*\)\s*,\s*LTL\s*\(\s*` + f.formula + `\s*\)\s*\)\s*$`),
			bare:     regexp.MustCompile(`^\s*` + f.formula + `\s*$`),
		})
	}
	return result
}

// Supported reports whether witness2test-match can check violations of p.
// A data race depends on a thread schedule that value injection cannot
// control, so no-data-race is recognized but not checked.
func (p Property) Supported() bool {
	return p != NoDataRace
}

// Name returns the name of p as SV-COMP reports a violation of it: a
// memory-safety subproperty without the enclosing valid-memsafety, e.g.
// "valid-deref".
func (p Property) Name() string {
	if sub, ok := strings.CutPrefix(string(p), "valid-memsafety("); ok {
		return strings.TrimSuffix(sub, ")")
	}
	return string(p)
}

// ParseFile parses the content of a property file: one CHECK expression per
// nonblank line. Order and duplicates are preserved.
func ParseFile(content string) ([]Property, error) {
	properties, err := parseLines(content, false)
	if err != nil {
		return nil, err
	}
	if len(properties) == 0 {
		return nil, fmt.Errorf("property file contains no properties")
	}
	return properties, nil
}

// ParseSpecification parses the specification string of a witness. Each
// nonblank line is either a full CHECK expression or a bare LTL formula such
// as "G ! overflow".
func ParseSpecification(specification string) ([]Property, error) {
	properties, err := parseLines(specification, true)
	if err != nil {
		return nil, err
	}
	if len(properties) == 0 {
		return nil, fmt.Errorf("specification is empty")
	}
	return properties, nil
}

func parseLines(content string, allowBare bool) ([]Property, error) {
	var properties []Property
	for lineIndex, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		matched, err := parseExpression(line, allowBare)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineIndex+1, err)
		}
		properties = append(properties, matched)
	}
	return properties, nil
}

func parseExpression(expression string, allowBare bool) (Property, error) {
	for _, candidate := range patterns {
		if candidate.check.MatchString(expression) || (allowBare && candidate.bare.MatchString(expression)) {
			return candidate.property, nil
		}
	}
	return "", fmt.Errorf("unrecognized property expression %q", expression)
}

// Contains reports whether properties includes wanted.
func Contains(properties []Property, wanted Property) bool {
	for _, p := range properties {
		if p == wanted {
			return true
		}
	}
	return false
}

// MissingFrom returns the properties of claimed that selected does not
// include, without duplicates and in the order of claimed.
func MissingFrom(claimed, selected []Property) []Property {
	var missing []Property
	for _, p := range claimed {
		if !Contains(selected, p) && !Contains(missing, p) {
			missing = append(missing, p)
		}
	}
	return missing
}
