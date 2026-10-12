// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
	bin := filepath.Join(dir, "witness2test")
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
	if !strings.Contains(string(out), "witness2test version") {
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

func TestBinaryOnSymbioticExample(t *testing.T) {
	bin := buildBinary(t)
	witness := filepath.Join("testdata", "sv-witnesses", "examples", "unsafe-program-example.symbiotic.witness-2.0.yml")
	program := filepath.Join("testdata", "sv-witnesses", "examples", "unsafe-program-example.c")
	out := t.TempDir()
	cmd := exec.Command(bin, "--witness", witness, "--program", program, "--output", out, "--time-per-run", "10")
	combined, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("witness2test failed: %v\n%s", err, combined)
	}
	if !strings.Contains(string(combined), "Verdict: Confirmed") {
		t.Errorf("expected Confirmed verdict, got:\n%s", combined)
	}
}
