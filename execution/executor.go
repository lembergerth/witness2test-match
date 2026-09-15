// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

// Package execution compiles the instrumented program against the embedded
// harness and runs it under a timeout, converting the exit code into a verdict.
package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"witness2test/internal/exitcodes"
)

// VerdictStatus enumerates the possible outcomes of running an instrumented test.
type VerdictStatus string

const (
	Confirmed           VerdictStatus = "Confirmed"
	Inconsistent        VerdictStatus = "WitnessInconsistent"
	NotConfirmed        VerdictStatus = "NotConfirmed"
	Timeout             VerdictStatus = "Timeout"
	WitnessUnsupported  VerdictStatus = "WitnessUnsupported"
)

// Verdict captures the outcome of one Run.
type Verdict struct {
	Status   VerdictStatus
	ExitCode int
	Stderr   string
}

// Compile compiles the instrumented program (programCode, fed via stdin) together
// with harnessPath into a binary written under outputDir, and returns its path.
func Compile(programCode, harnessPath, outputDir string) (string, error) {
	if err := checkNoLeadingDash(harnessPath, "harness path"); err != nil {
		return "", err
	}
	if err := checkNoLeadingDash(outputDir, "output dir"); err != nil {
		return "", err
	}

	binary := filepath.Join(outputDir, "program")
	args := []string{
		harnessPath,
		"-x", "c", "-",
		"-o", binary,
		"-std=gnu11",
		"-Wno-attributes",
		"-lm",
	}
	cmd := exec.Command("gcc", args...)
	cmd.Stdin = strings.NewReader(programCode)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gcc compilation failed: %w\n%s", err, stderr.String())
	}
	return binary, nil
}

// Run executes binary with a wall-clock timeout. On timeout, the entire process
// group is killed (so any child processes the test spawns are reaped).
//
// The verdict status is derived from the program's exit code via the constants
// in internal/exitcodes. Run never returns WitnessUnsupported — that status is
// produced upstream when the witness has no extractable injection points.
func Run(ctx context.Context, binary string, timeout time.Duration) (Verdict, error) {
	if err := checkNoLeadingDash(binary, "binary path"); err != nil {
		return Verdict{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binary)
	// Empty stdin: the instrumented program is not expected to read input.
	cmd.Stdin = strings.NewReader("")
	// Sanitized environment.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.SysProcAttr = sysProcAttr()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	startErr := cmd.Start()
	if startErr != nil {
		return Verdict{}, fmt.Errorf("failed to start binary %s: %w", binary, startErr)
	}

	// Wait in a goroutine so that we can race against ctx.Done() and kill the
	// process group on timeout.
	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()

	var waitErr error
	select {
	case <-runCtx.Done():
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			killProcessGroup(cmd.Process.Pid)
			<-doneCh
			return Verdict{Status: Timeout, ExitCode: -1, Stderr: stderr.String()}, nil
		}
		killProcessGroup(cmd.Process.Pid)
		<-doneCh
		return Verdict{Status: Timeout, ExitCode: -1, Stderr: stderr.String()}, runCtx.Err()
	case waitErr = <-doneCh:
	}

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return Verdict{}, fmt.Errorf("execution failed: %w", waitErr)
		}
	}

	status := NotConfirmed
	switch exitCode {
	case exitcodes.ViolationReached:
		status = Confirmed
	case exitcodes.WitnessInconsistent:
		status = Inconsistent
	}
	return Verdict{Status: status, ExitCode: exitCode, Stderr: stderr.String()}, nil
}

func checkNoLeadingDash(path, what string) error {
	if strings.HasPrefix(filepath.Base(path), "-") {
		return fmt.Errorf("%s %q starts with '-' (rejected to prevent argv injection)", what, path)
	}
	return nil
}

// killProcessGroup tries to kill the process group leader's group; on platforms
// without process-group support this falls back to killing the leader only.
func killProcessGroup(pid int) {
	// Negative pid asks the kernel to signal the whole group.
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
