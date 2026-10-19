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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go not available: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "witness2test-match")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func TestBinaryVersion(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "witness2test-match version") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestBinaryMissingArgs(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 2 {
		t.Errorf("expected exit 2 for missing args, got %d\noutput: %s", cmd.ProcessState.ExitCode(), out)
	}
}

func TestBinaryILP32Violation(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	program := filepath.Join(dir, "program.c")
	witness := filepath.Join(dir, "witness.yml")
	source := strings.Replace(programWithSingleNondet, "if (x == 42)",
		"if (x == 42 && sizeof(int) == 4 && sizeof(long) == 4 && sizeof(void *) == 4)", 1)
	writeFile(t, program, source)
	writeFile(t, witness, witnessHitsViolation)
	for _, tt := range []struct {
		model    string
		verdict  string
		exitCode int
	}{
		{"ILP32", "Confirmed unreach-call", 213},
		{"LP64", "NotConfirmed", 0},
	} {
		t.Run(tt.model, func(t *testing.T) {
			out := t.TempDir()
			combined, err := exec.Command(bin, "--witness", witness, "--program", program,
				"--output", out, "--model", tt.model, "--time-per-run", "5").CombinedOutput()
			if err != nil {
				t.Fatalf("witness2test-match failed: %v\n%s", err, combined)
			}
			want := fmt.Sprintf("Verdict: %s (exit code %d). Instrumented program: %s\n",
				tt.verdict, tt.exitCode, filepath.Join(out, "instrumented_program.c"))
			if string(combined) != want {
				t.Errorf("output = %q, want %q", combined, want)
			}
		})
	}
}

func TestBinaryOnSymbioticExample(t *testing.T) {
	bin := buildBinary(t)
	witness := filepath.Join("testdata", "sv-witnesses", "examples", "unsafe-program-example.symbiotic.witness-2.0.yml")
	program := filepath.Join("testdata", "sv-witnesses", "examples", "unsafe-program-example.c")
	tests := []struct {
		name     string
		content  string
		property string
	}{
		{"default", "", "unreach-call"},
		{"unreach-call", "CHECK( init(main()), LTL(G ! call(reach_error())) )", "unreach-call"},
		{"valid-free", "CHECK( init(main()), LTL(G valid-free) )", "valid-memsafety(valid-free)"},
		{"valid-deref", "CHECK( init(main()), LTL(G valid-deref) )", "valid-memsafety(valid-deref)"},
		{"valid-memtrack", "CHECK( init(main()), LTL(G valid-memtrack) )", "valid-memsafety(valid-memtrack)"},
		{"no-overflow", "CHECK( init(main()), LTL(G ! overflow) )", "no-overflow"},
		{"no-data-race", "CHECK( init(main()), LTL(G ! data-race) )", "no-data-race"},
		{"valid-memcleanup", "CHECK( init(main()), LTL(G valid-memcleanup) )", "valid-memcleanup"},
		{"multiple overflow first", "CHECK(init(main()),LTL(G ! overflow))\nCHECK(init(main()),LTL(G ! call(reach_error())))", "no-overflow"},
		{"multiple unreach first", "CHECK(init(main()),LTL(G ! call(reach_error())))\nCHECK(init(main()),LTL(G ! overflow))", "unreach-call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			args := []string{"--witness", witness, "--program", program, "--output", out, "--time-per-run", "10"}
			if tt.content != "" {
				path := filepath.Join(t.TempDir(), "properties.prp")
				writeFile(t, path, tt.content)
				args = append(args, "--property", path)
			}
			combined, err := exec.Command(bin, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("witness2test-match failed: %v\n%s", err, combined)
			}
			want := fmt.Sprintf("Verdict: Confirmed %s (exit code 213). Instrumented program: %s\n", tt.property, filepath.Join(out, "instrumented_program.c"))
			if string(combined) != want {
				t.Errorf("output = %q, want %q", combined, want)
			}
		})
	}
}
