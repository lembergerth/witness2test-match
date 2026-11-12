// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package property

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseProperties(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		properties []Property
	}{
		{"unreach-call", "CHECK( init(main()), LTL(G ! call(reach_error())) )", []Property{UnreachCall}},
		{"valid-free", "CHECK( init(main()), LTL(G valid-free) )", []Property{"valid-memsafety(valid-free)"}},
		{"valid-deref", "CHECK( init(main()), LTL(G valid-deref) )", []Property{"valid-memsafety(valid-deref)"}},
		{"valid-memtrack", "CHECK( init(main()), LTL(G valid-memtrack) )", []Property{"valid-memsafety(valid-memtrack)"}},
		{"overflow", "CHECK( init(main()), LTL(G ! overflow) )", []Property{"no-overflow"}},
		{"data-race", "CHECK( init(main()), LTL(G ! data-race) )", []Property{"no-data-race"}},
		{"memcleanup", "CHECK( init(main()), LTL(G valid-memcleanup) )", []Property{"valid-memcleanup"}},
		{"compact", "CHECK(init(main()),LTL(G ! overflow))", []Property{"no-overflow"}},
		{"whitespace", " \tCHECK \t(\tinit \t( main \t( \t)\t) \t,\t LTL \t( \tG\t!\tcall \t( reach_error \t( \t) \t) \t)\t)\t ", []Property{UnreachCall}},
		{"multiple", "CHECK(init(main()),LTL(G ! overflow))\nCHECK(init(main()),LTL(G valid-free))\nCHECK(init(main()),LTL(G ! call(reach_error())))", []Property{"no-overflow", "valid-memsafety(valid-free)", UnreachCall}},
		{"duplicates", "CHECK(init(main()),LTL(G valid-deref))\nCHECK(init(main()),LTL(G valid-deref))\n", []Property{"valid-memsafety(valid-deref)", "valid-memsafety(valid-deref)"}},
		{"blank lines and CRLF", "\r\n \t\r\nCHECK(init(main()),LTL(G valid-memtrack))\r\n\r\nCHECK(init(main()),LTL(G valid-memcleanup))\r\n", []Property{"valid-memsafety(valid-memtrack)", "valid-memcleanup"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			properties, err := ParseFile(tt.content)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			if !reflect.DeepEqual(properties, tt.properties) {
				t.Errorf("properties = %q, want %q", properties, tt.properties)
			}
		})
	}
}

func TestParsePropertiesRejectsEmptyFile(t *testing.T) {
	for _, content := range []string{"", " \t\r\n\n"} {
		properties, err := ParseFile(content)
		if properties != nil || err == nil || err.Error() != "property file contains no properties" {
			t.Errorf("ParseFile(%q) = %v, %v", content, properties, err)
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
			properties, err := ParseFile("\nCHECK(init(main()),LTL(G ! overflow))\n" + expression)
			wantError := fmt.Sprintf("line 3: unrecognized property expression %q", expression)
			if properties != nil || err == nil || err.Error() != wantError {
				t.Errorf("ParseFile = %v, %v; want nil, %q", properties, err, wantError)
			}
		})
	}
}

func TestParseSpecification(t *testing.T) {
	tests := []struct {
		name          string
		specification string
		properties    []Property
	}{
		{"bare unreach", "G ! call(reach_error())", []Property{UnreachCall}},
		{"bare overflow", "G ! overflow", []Property{NoOverflow}},
		{"bare deref with spaces", "  G   valid-deref ", []Property{ValidDeref}},
		{"full check", "CHECK( init(main()), LTL(G valid-free) )", []Property{ValidFree}},
		{"memcleanup", "G valid-memcleanup", []Property{ValidMemcleanup}},
		{"data race", "CHECK( init(main()), LTL(G ! data-race) )", []Property{NoDataRace}},
		{"multiple lines", "CHECK( init(main()), LTL(G valid-free) )\nCHECK( init(main()), LTL(G valid-deref) )\nG valid-memtrack\n", []Property{ValidFree, ValidDeref, ValidMemtrack}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			properties, err := ParseSpecification(tt.specification)
			if err != nil {
				t.Fatalf("ParseSpecification: %v", err)
			}
			if !reflect.DeepEqual(properties, tt.properties) {
				t.Errorf("properties = %q, want %q", properties, tt.properties)
			}
		})
	}
}

func TestParseSpecificationRejectsUnknown(t *testing.T) {
	for _, specification := range []string{"", "  \n", "F end", "G valid-free; exit(1)", "CHECK( init(main()), LTL(F end) )"} {
		if properties, err := ParseSpecification(specification); err == nil {
			t.Errorf("ParseSpecification(%q) = %v, want error", specification, properties)
		}
	}
}

func TestSupported(t *testing.T) {
	for _, p := range []Property{UnreachCall, NoOverflow, ValidFree, ValidDeref, ValidMemtrack, ValidMemcleanup} {
		if !p.Supported() {
			t.Errorf("%s should be supported", p)
		}
	}
	if NoDataRace.Supported() {
		t.Error("no-data-race must not be supported")
	}
}

func TestMissingFrom(t *testing.T) {
	selected := []Property{ValidFree, ValidDeref, ValidMemtrack}
	if missing := MissingFrom([]Property{ValidDeref}, selected); len(missing) != 0 {
		t.Errorf("missing = %v, want none", missing)
	}
	missing := MissingFrom([]Property{ValidDeref, NoOverflow, UnreachCall, NoOverflow}, selected)
	if !reflect.DeepEqual(missing, []Property{NoOverflow, UnreachCall}) {
		t.Errorf("missing = %v, want [no-overflow unreach-call]", missing)
	}
}

func TestContains(t *testing.T) {
	if !Contains([]Property{NoOverflow, ValidFree}, ValidFree) || Contains([]Property{NoOverflow}, ValidFree) {
		t.Error("Contains gives wrong answers")
	}
}
