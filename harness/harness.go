// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

// Package harness exposes the minimal C harness embedded into witness2test.
// The harness defines reach_error() (which exits with exitcodes.ViolationReached)
// and weak default __VERIFIER_nondet_*() implementations.
package harness

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed harness.c.template
var harnessContent string

// Content returns the embedded harness source. Exposed for testing.
func Content() string {
	return harnessContent
}

// WriteHarnessFile writes the embedded harness C source to filePath.
// It creates the parent directory if it does not exist.
func WriteHarnessFile(filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(harnessContent), 0o644)
}
