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
	propertyPath := fs.String("property", "", "Path to the property file (default: unreach-call)")
	outputDir := fs.String("output", "output", "Path to the output directory")
	timePerRun := fs.Int("time-per-run", 60, "Timeout for the compiled test program (seconds)")
	model := "LP64"
	fs.Func("model", "Data model: ILP32 or LP64 (default LP64)", func(value string) error {
		if value != "ILP32" && value != "LP64" {
			return fmt.Errorf("expected ILP32 or LP64")
		}
		model = value
		return nil
	})
	printVersion := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2, ""
	}
	if *printVersion {
		if _, err := fmt.Fprintf(stdout, "witness2test-match version %s\n", version); err != nil {
			return 1, fmt.Sprintf("witness2test-match: failed to write version: %v", err)
		}
		return 0, ""
	}
	if *witnessPath == "" || *programPath == "" {
		fs.Usage()
		return 2, "Error: both --witness and --program are required"
	}
	properties, err := readProperties(*propertyPath)
	if err != nil {
		return 1, fmt.Sprintf("witness2test-match: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "witness2test-match-")
	if err != nil {
		return 1, fmt.Sprintf("failed to create temp dir: %v", err)
	}
	defer func() {
		// Temporary-file cleanup must not replace the execution verdict.
		_ = os.RemoveAll(tmpDir)
	}()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return 1, fmt.Sprintf("failed to create output dir %s: %v", *outputDir, err)
	}

	verdict, instrumentedPath, derr := turnWitnessToTest(
		*witnessPath, *programPath, tmpDir, *outputDir,
		executionOptions{timeout: time.Duration(*timePerRun) * time.Second, model: model},
	)
	if derr != nil {
		return 1, fmt.Sprintf("witness2test-match: %v", derr)
	}
	if _, err := fmt.Fprintln(stdout, formatVerdict(verdict, instrumentedPath, properties)); err != nil {
		return 1, fmt.Sprintf("witness2test-match: failed to write verdict: %v", err)
	}
	return 0, ""
}

func readProperties(propertyPath string) ([]property, error) {
	if propertyPath == "" {
		return []property{unreachCall}, nil
	}
	content, err := os.ReadFile(propertyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read property file: %w", err)
	}
	properties, err := parseProperties(string(content))
	if err != nil {
		return nil, fmt.Errorf("property file %q: %w", propertyPath, err)
	}
	return properties, nil
}

type executionOptions struct {
	timeout time.Duration
	model   string
}

// turnWitnessToTest executes the full pipeline and returns (verdict, instrumented-path, error).
// The instrumented-path is always populated (the file is always written) so the caller can
// reference it in the final verdict message.
func turnWitnessToTest(witnessPath, programPath, tempDir, outputDir string, options executionOptions) (execution.Verdict, string, error) {
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

	binary, cerr := execution.Compile(instrumented, harnessPath, execution.CompileOptions{OutputDir: tempDir, Model: options.model})
	if cerr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("compile: %w", cerr)
	}

	verdict, rerr := execution.Run(context.Background(), binary, options.timeout)
	if rerr != nil {
		return verdict, instrumentedPath, fmt.Errorf("run: %w", rerr)
	}
	return verdict, instrumentedPath, nil
}

func formatVerdict(v execution.Verdict, instrumentedPath string, properties []property) string {
	status := string(v.Status)
	if v.Status == execution.Confirmed {
		status += " " + string(properties[0])
	}
	msg := fmt.Sprintf("Verdict: %s (exit code %d). Instrumented program: %s",
		status, v.ExitCode, instrumentedPath)
	if v.Stderr != "" {
		msg += "\n--- program stderr ---\n" + v.Stderr
	}
	return msg
}
