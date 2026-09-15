// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

package execution

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"witness2test/internal/exitcodes"
)

var gccAvailable bool

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("gcc"); err == nil {
		gccAvailable = true
	}
	os.Exit(m.Run())
}

func requireGCC(t *testing.T) {
	t.Helper()
	if !gccAvailable {
		t.Skip("gcc not available; skipping integration-style test")
	}
}

func compileAndRun(t *testing.T, programCode string) Verdict {
	t.Helper()
	requireGCC(t)
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(harness, []byte("// empty harness for unit test\n"), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary, err := Compile(programCode, harness, dir)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	v, err := Run(context.Background(), binary, 5*time.Second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return v
}

func TestRunConfirmedFromExitCode(t *testing.T) {
	src := fmt.Sprintf("extern void _Exit(int);\nint main(void){ _Exit(%d); return 0; }\n", exitcodes.ViolationReached)
	v := compileAndRun(t, src)
	if v.Status != Confirmed || v.ExitCode != exitcodes.ViolationReached {
		t.Errorf("got %+v", v)
	}
}

func TestRunInconsistentFromExitCode(t *testing.T) {
	src := fmt.Sprintf("extern void _Exit(int);\nint main(void){ _Exit(%d); return 0; }\n", exitcodes.WitnessInconsistent)
	v := compileAndRun(t, src)
	if v.Status != Inconsistent || v.ExitCode != exitcodes.WitnessInconsistent {
		t.Errorf("got %+v", v)
	}
}

func TestRunNotConfirmedFromCleanExit(t *testing.T) {
	v := compileAndRun(t, "int main(void){ return 0; }\n")
	if v.Status != NotConfirmed {
		t.Errorf("got %+v, want NotConfirmed", v)
	}
}

func TestRunNotConfirmedFromNonzeroExit(t *testing.T) {
	v := compileAndRun(t, "int main(void){ return 7; }\n")
	if v.Status != NotConfirmed || v.ExitCode != 7 {
		t.Errorf("got %+v", v)
	}
}

func TestRunTimeoutKillsProgram(t *testing.T) {
	requireGCC(t)
	src := "int main(void){ for(;;){} return 0; }\n"
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(harness, []byte(""), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary, err := Compile(src, harness, dir)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	start := time.Now()
	v, err := Run(context.Background(), binary, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if v.Status != Timeout {
		t.Errorf("got %+v, want Timeout", v)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Run took %v; timeout did not kill quickly", elapsed)
	}
}

func TestCompileFailureSurfacesStderr(t *testing.T) {
	requireGCC(t)
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(harness, []byte(""), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	_, err := Compile("not C at all !!!\n", harness, dir)
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "compilation failed") {
		t.Errorf("error should describe compilation failure: %v", err)
	}
}

func TestCompileRejectsLeadingDashPaths(t *testing.T) {
	_, err := Compile("int main(){return 0;}", "-suspicious.c", t.TempDir())
	if err == nil {
		t.Error("Compile should reject harness path starting with '-'")
	}
	dir := t.TempDir()
	_, err = Compile("int main(){return 0;}", filepath.Join(dir, "harness.c"), "/tmp/-bad")
	// outputDir basename "-bad" must be rejected.
	if err == nil {
		t.Error("Compile should reject output dir starting with '-'")
	}
}

func TestRunRejectsLeadingDashBinary(t *testing.T) {
	_, err := Run(context.Background(), "-evil", time.Second)
	if err == nil {
		t.Error("Run should reject binary path starting with '-'")
	}
}

func TestRunStartFailureSurfacesError(t *testing.T) {
	_, err := Run(context.Background(), "/path/that/does/not/exist", time.Second)
	if err == nil {
		t.Error("Run should error when the binary does not exist")
	}
}

func TestRunParentContextCanceled(t *testing.T) {
	requireGCC(t)
	src := "int main(void){ for(;;){} return 0; }\n"
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness.c")
	if err := os.WriteFile(harness, []byte(""), 0o644); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary, err := Compile(src, harness, dir)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	v, err := Run(ctx, binary, 10*time.Second)
	// Parent cancellation surfaces as either a Timeout verdict + non-nil error
	// (context.Canceled) or a clean Timeout if the deadline was reached first.
	if v.Status != Timeout {
		t.Errorf("expected Timeout verdict on parent cancel, got %+v", v)
	}
	if err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Logf("Run error on parent cancel: %v", err)
	}
}
