// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"witness2test/execution"
	"witness2test/harness"
	"witness2test/instrument"
	"witness2test/witness"
)

// Automatically replaced on build via -ldflags.
var version = "undefined"

func main() { os.Exit(mainWithArgs(os.Args[1:])) }

func mainWithArgs(args []string) int {
	exit, msg := run(args, os.Stdout, os.Stderr)
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
	return exit
}

// run is the testable entry point. It returns the desired process exit code
// and an optional final message to print to stderr.
func run(args []string, stdout, stderr *os.File) (int, string) {
	fs := flag.NewFlagSet("witness2test-match", flag.ContinueOnError)
	fs.SetOutput(stderr)
	witnessPath := fs.String("witness", "", "Path to the v2 violation witness YAML file (required)")
	programPath := fs.String("program", "", "Path to the C program file (required)")
	outputDir := fs.String("output", "output", "Path to the output directory")
	timePerRun := fs.Int("time-per-run", 60, "Timeout for the compiled test program (seconds)")
	printVersion := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2, ""
	}
	if *printVersion {
		fmt.Fprintf(stdout, "witness2test-match version %s\n", version)
		return 0, ""
	}
	if *witnessPath == "" || *programPath == "" {
		fs.Usage()
		return 2, "Error: both --witness and --program are required"
	}

	tmpDir, err := os.MkdirTemp("", "witness2test-match-")
	if err != nil {
		return 1, fmt.Sprintf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return 1, fmt.Sprintf("failed to create output dir %s: %v", *outputDir, err)
	}

	verdict, instrumentedPath, derr := turnWitnessToTest(
		*witnessPath, *programPath, tmpDir, *outputDir,
		time.Duration(*timePerRun)*time.Second,
	)
	if derr != nil {
		return 1, fmt.Sprintf("witness2test-match: %v", derr)
	}
	fmt.Fprintln(stdout, formatVerdict(verdict, instrumentedPath))
	return 0, ""
}

// turnWitnessToTest executes the full pipeline and returns (verdict, instrumented-path, error).
// The instrumented-path is always populated (the file is always written) so the caller can
// reference it in the final verdict message.
func turnWitnessToTest(witnessPath, programPath, tempDir, outputDir string, timeout time.Duration) (execution.Verdict, string, error) {
	witnessBytes, err := os.ReadFile(witnessPath)
	if err != nil {
		return execution.Verdict{}, "", fmt.Errorf("failed to read witness file: %w", err)
	}
	programBytes, err := os.ReadFile(programPath)
	if err != nil {
		return execution.Verdict{}, "", fmt.Errorf("failed to read program file: %w", err)
	}
	programSrc := string(programBytes)
	programBasename := filepath.Base(programPath)

	points, counts, err := witness.Parse(witnessBytes, programBasename)
	if err != nil {
		return execution.Verdict{}, "", fmt.Errorf("witness parse: %w", err)
	}
	injections := witness.GroupByLocation(points)
	sites := instrument.CollectNondetCalls(programSrc)
	reachErrorSites := instrument.CollectReachErrorCalls(programSrc)

	instrumentedPath := filepath.Join(outputDir, "instrumented_program.c")

	if len(injections) == 0 {
		// Always emit the program as-is so the path is meaningful even on the
		// unsupported-witness path.
		if werr := os.WriteFile(instrumentedPath, programBytes, 0o644); werr != nil {
			return execution.Verdict{}, instrumentedPath, fmt.Errorf("failed to write instrumented program: %w", werr)
		}
		return execution.Verdict{
			Status: execution.WitnessUnsupported,
			Stderr: fmt.Sprintf("witness has no function_return waypoints we can interpret (waypoints seen: %s)", counts.Summary()),
		}, instrumentedPath, nil
	}

	instrumented, err := instrument.Instrument(programSrc, injections, sites, reachErrorSites)
	if err != nil {
		return execution.Verdict{}, "", fmt.Errorf("instrument: %w", err)
	}
	if werr := os.WriteFile(instrumentedPath, []byte(instrumented), 0o644); werr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("failed to write instrumented program: %w", werr)
	}

	harnessPath := filepath.Join(tempDir, "harness.c")
	if herr := harness.WriteHarnessFile(harnessPath); herr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("failed to write harness: %w", herr)
	}

	binary, cerr := execution.Compile(instrumented, harnessPath, tempDir)
	if cerr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("compile: %w", cerr)
	}

	verdict, rerr := execution.Run(context.Background(), binary, timeout)
	if rerr != nil {
		return verdict, instrumentedPath, fmt.Errorf("run: %w", rerr)
	}
	return verdict, instrumentedPath, nil
}

func formatVerdict(v execution.Verdict, instrumentedPath string) string {
	msg := fmt.Sprintf("Verdict: %s (exit code %d). Instrumented program: %s",
		v.Status, v.ExitCode, instrumentedPath)
	if v.Stderr != "" {
		msg += "\n--- program stderr ---\n" + v.Stderr
	}
	return msg
}
