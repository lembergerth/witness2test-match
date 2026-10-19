// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"strings"
)

type property string

const unreachCall property = "unreach-call"

var propertyPatterns = []struct {
	property property
	pattern  *regexp.Regexp
}{
	{unreachCall, propertyPattern(`G\s+!\s+call\s*\(\s*reach_error\s*\(\s*\)\s*\)`)},
	{"valid-memsafety(valid-free)", propertyPattern(`G\s+valid-free`)},
	{"valid-memsafety(valid-deref)", propertyPattern(`G\s+valid-deref`)},
	{"valid-memsafety(valid-memtrack)", propertyPattern(`G\s+valid-memtrack`)},
	{"no-overflow", propertyPattern(`G\s+!\s+overflow`)},
	{"no-data-race", propertyPattern(`G\s+!\s+data-race`)},
	{"valid-memcleanup", propertyPattern(`G\s+valid-memcleanup`)},
}

func propertyPattern(formula string) *regexp.Regexp {
	return regexp.MustCompile(`^\s*CHECK\s*\(\s*init\s*\(\s*main\s*\(\s*\)\s*\)\s*,\s*LTL\s*\(\s*` + formula + `\s*\)\s*\)\s*$`)
}

func parseProperties(content string) ([]property, error) {
	var properties []property
	for lineIndex, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		matchedProperty, err := parseProperty(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineIndex+1, err)
		}
		properties = append(properties, matchedProperty)
	}
	if len(properties) == 0 {
		return nil, fmt.Errorf("property file contains no properties")
	}
	return properties, nil
}

func parseProperty(expression string) (property, error) {
	for _, candidate := range propertyPatterns {
		if candidate.pattern.MatchString(expression) {
			return candidate.property, nil
		}
	}
	return "", fmt.Errorf("unrecognized property expression %q", expression)
}
