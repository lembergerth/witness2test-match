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
	"reflect"
	"testing"
)

func TestParseProperties(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		properties []property
	}{
		{"unreach-call", "CHECK( init(main()), LTL(G ! call(reach_error())) )", []property{unreachCall}},
		{"valid-free", "CHECK( init(main()), LTL(G valid-free) )", []property{"valid-memsafety(valid-free)"}},
		{"valid-deref", "CHECK( init(main()), LTL(G valid-deref) )", []property{"valid-memsafety(valid-deref)"}},
		{"valid-memtrack", "CHECK( init(main()), LTL(G valid-memtrack) )", []property{"valid-memsafety(valid-memtrack)"}},
		{"overflow", "CHECK( init(main()), LTL(G ! overflow) )", []property{"no-overflow"}},
		{"data-race", "CHECK( init(main()), LTL(G ! data-race) )", []property{"no-data-race"}},
		{"memcleanup", "CHECK( init(main()), LTL(G valid-memcleanup) )", []property{"valid-memcleanup"}},
		{"compact", "CHECK(init(main()),LTL(G ! overflow))", []property{"no-overflow"}},
		{"whitespace", " \tCHECK \t(\tinit \t( main \t( \t)\t) \t,\t LTL \t( \tG\t!\tcall \t( reach_error \t( \t) \t) \t)\t)\t ", []property{unreachCall}},
		{"multiple", "CHECK(init(main()),LTL(G ! overflow))\nCHECK(init(main()),LTL(G valid-free))\nCHECK(init(main()),LTL(G ! call(reach_error())))", []property{"no-overflow", "valid-memsafety(valid-free)", unreachCall}},
		{"duplicates", "CHECK(init(main()),LTL(G valid-deref))\nCHECK(init(main()),LTL(G valid-deref))\n", []property{"valid-memsafety(valid-deref)", "valid-memsafety(valid-deref)"}},
		{"blank lines and CRLF", "\r\n \t\r\nCHECK(init(main()),LTL(G valid-memtrack))\r\n\r\nCHECK(init(main()),LTL(G valid-memcleanup))\r\n", []property{"valid-memsafety(valid-memtrack)", "valid-memcleanup"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			properties, err := parseProperties(tt.content)
			if err != nil {
				t.Fatalf("parseProperties: %v", err)
			}
			if !reflect.DeepEqual(properties, tt.properties) {
				t.Errorf("properties = %q, want %q", properties, tt.properties)
			}
		})
	}
}

func TestParsePropertiesRejectsEmptyFile(t *testing.T) {
	for _, content := range []string{"", " \t\r\n\n"} {
		properties, err := parseProperties(content)
		if properties != nil || err == nil || err.Error() != "property file contains no properties" {
			t.Errorf("parseProperties(%q) = %v, %v", content, properties, err)
		}
	}
}

func TestParsePropertiesRejectsUnrecognizedExpressions(t *testing.T) {
	for _, expression := range []string{
		"CHECK(init(main()),LTL(G termination))",
		"CHECK(init(other()),LTL(G valid-free))",
		"CHECK(init(main()),LTL(G ! valid-free))",
		"CHECK(init(main()),LTL(G overflow))",
		"CHECK(init(main()),LTL(G! overflow))",
		"CHECK(init(main()),LTL(G !overflow))",
		"CHECK(init(main()),LTL(G valid -free))",
		"CHECK(init(main()),LTL(G ! call(reach_ error())))",
		"CHECK(init(main()),LTL(G valid-free)",
		"prefix CHECK(init(main()),LTL(G valid-free))",
		"CHECK(init(main()),LTL(G valid-free)) suffix",
		"CHECK(init(main()),LTL(G valid-free)) CHECK(init(main()),LTL(G valid-deref))",
		"CHECK(init(main()),LTL(G valid-free)); exit(213);",
		"CHECKinitmain,LTLG valid-free",
	} {
		t.Run(expression, func(t *testing.T) {
			properties, err := parseProperties("\nCHECK(init(main()),LTL(G ! overflow))\n" + expression)
			wantError := fmt.Sprintf("line 3: unrecognized property expression %q", expression)
			if properties != nil || err == nil || err.Error() != wantError {
				t.Errorf("parseProperties = %v, %v; want nil, %q", properties, err, wantError)
			}
		})
	}
}
