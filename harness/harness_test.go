// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"witness2test/internal/exitcodes"
)

func TestWriteHarnessFileWritesEmbeddedContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "harness.c")
	if err := WriteHarnessFile(target); err != nil {
		t.Fatalf("WriteHarnessFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read written harness: %v", err)
	}
	if string(got) != Content() {
		t.Error("written harness must equal the embedded template")
	}
}

func TestReachErrorExitsWithExitcodesValue(t *testing.T) {
	// Pin the embedded harness's _Exit literal to exitcodes.ViolationReached.
	re := regexp.MustCompile(`reach_error\s*\(\s*void\s*\)\s*\{\s*_Exit\((\d+)\)`)
	m := re.FindStringSubmatch(Content())
	if m == nil {
		t.Fatal("could not find reach_error definition's _Exit(N) literal in harness template")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse _Exit literal: %v", err)
	}
	if n != exitcodes.ViolationReached {
		t.Errorf("reach_error exits with %d, want exitcodes.ViolationReached (%d)", n, exitcodes.ViolationReached)
	}
}

func TestWriteHarnessFileMkdirError(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file where we'll then try to use as a directory parent.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Try to write inside the blocker (which is a file, not a directory).
	err := WriteHarnessFile(filepath.Join(blocker, "harness.c"))
	if err == nil {
		t.Fatal("expected mkdir error when parent path is a regular file")
	}
}

func TestHarnessProvidesCommonNondetVariants(t *testing.T) {
	want := []string{
		"__VERIFIER_nondet_int", "__VERIFIER_nondet_uint", "__VERIFIER_nondet_uchar",
		"__VERIFIER_nondet_bool", "__VERIFIER_nondet_pointer", "__VERIFIER_nondet_long",
	}
	for _, name := range want {
		if !strings.Contains(Content(), name) {
			t.Errorf("harness should provide a weak default for %s", name)
		}
	}
}
