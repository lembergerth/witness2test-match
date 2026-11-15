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
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"witness2test/execution"
	"witness2test/harness"
	"witness2test/instrument"
	"witness2test/property"
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
			return 1, errorMessage(fmt.Errorf("failed to write version: %w", err))
		}
		return 0, ""
	}
	if *witnessPath == "" || *programPath == "" {
		fs.Usage()
		return 2, errorMessage(errors.New("both --witness and --program are required"))
	}
	properties, err := readProperties(*propertyPath)
	if err != nil {
		return 1, errorMessage(err)
	}

	tmpDir, err := os.MkdirTemp("", "witness2test-match-")
	if err != nil {
		return 1, errorMessage(fmt.Errorf("failed to create temp dir: %w", err))
	}
	defer func() {
		// Temporary-file cleanup must not replace the execution verdict.
		_ = os.RemoveAll(tmpDir)
	}()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return 1, errorMessage(fmt.Errorf("failed to create output dir %s: %w", *outputDir, err))
	}

	verdict, instrumentedPath, derr := turnWitnessToTest(
		*witnessPath, *programPath, tmpDir, *outputDir,
		executionOptions{timeout: time.Duration(*timePerRun) * time.Second, model: model, properties: properties},
	)
	if derr != nil {
		return 1, errorMessage(derr)
	}
	if _, err := fmt.Fprintln(stdout, formatVerdict(verdict, instrumentedPath)); err != nil {
		return 1, errorMessage(fmt.Errorf("failed to write verdict: %w", err))
	}
	return 0, ""
}

func readProperties(propertyPath string) ([]property.Property, error) {
	if propertyPath == "" {
		return []property.Property{property.UnreachCall}, nil
	}
	content, err := os.ReadFile(propertyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read property file: %w", err)
	}
	properties, err := property.ParseFile(string(content))
	if err != nil {
		return nil, fmt.Errorf("property file %q: %w", propertyPath, err)
	}
	return properties, nil
}

type executionOptions struct {
	timeout time.Duration
	model   string
	// properties are the properties selected on the command line.
	properties []property.Property
}

// maxPrintedNotes bounds how many notes about unmatched waypoints are kept;
// witnesses can carry hundreds of waypoints the tool does not interpret.
const maxPrintedNotes = 10

// resolveCheckedProperties determines which properties to check: those the
// witness claims in its specification. The selected properties (from the
// command line) must include every claimed property. A witness without a
// recognizable specification is checked against the selected properties.
func resolveCheckedProperties(selected []property.Property, specification string) (checked []property.Property, notes []string, err error) {
	if strings.TrimSpace(specification) == "" {
		return unique(selected), []string{"witness states no specification; checking the selected properties"}, nil
	}
	claimed, perr := property.ParseSpecification(specification)
	if perr != nil {
		return unique(selected), []string{fmt.Sprintf("witness specification %q is not recognized; checking the selected properties", specification)}, nil
	}
	if missing := property.MissingFrom(claimed, selected); len(missing) > 0 {
		return nil, nil, fmt.Errorf("witness claims a violation of %s, which the selected properties (%s) do not include",
			joinProperties(missing), joinProperties(unique(selected)))
	}
	return unique(claimed), nil, nil
}

func unique(properties []property.Property) []property.Property {
	return property.MissingFrom(properties, nil)
}

func joinProperties(properties []property.Property) string {
	names := make([]string, len(properties))
	for i, p := range properties {
		names[i] = string(p)
	}
	return strings.Join(names, ", ")
}

func unsupportedProperties(properties []property.Property) []property.Property {
	var unsupported []property.Property
	for _, p := range properties {
		if !p.Supported() {
			unsupported = append(unsupported, p)
		}
	}
	return unsupported
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

	parsed, err := witness.ParseWitness(witnessBytes, programBasename)
	if err != nil {
		return execution.Verdict{}, "", &taggedError{tag: tagInvalidWitness, err: err}
	}
	if parsed.ViolationSequences == 0 {
		return execution.Verdict{}, "", &taggedError{tag: tagInvalidWitness, err: fmt.Errorf(
			"the witness contains no violation_sequence entry (found: %s)", describeEntryTypes(parsed.EntryTypes))}
	}
	// The format requires a final segment with a target waypoint. Target
	// waypoints in other files or with another action count as well: only a
	// witness without any target is invalid.
	if parsed.Counts.Target == 0 {
		return execution.Verdict{}, "", &taggedError{tag: tagInvalidWitness, err: fmt.Errorf(
			"the violation sequence has no target waypoint (found: %s)", parsed.Counts.Summary())}
	}
	selected := options.properties
	if len(selected) == 0 {
		selected = []property.Property{property.UnreachCall}
	}
	checked, notes, err := resolveCheckedProperties(selected, parsed.Specification)
	if err != nil {
		return execution.Verdict{}, "", err
	}

	if model := effectiveModel(options.model); parsed.DataModel != "" && parsed.DataModel != model {
		// The caller's --model defines the task; the witness is only told apart.
		notes = append(notes, fmt.Sprintf("witness states data model %s, but the test is built for %s (--model)", parsed.DataModel, model))
	}

	instrumentedPath := filepath.Join(outputDir, "instrumented_program.c")
	// stopEarly reports a verdict without executing anything. The program is
	// still emitted as-is so the path in the verdict line is meaningful.
	stopEarly := func(status execution.VerdictStatus, reason string) (execution.Verdict, string, error) {
		if werr := os.WriteFile(instrumentedPath, programBytes, 0o644); werr != nil {
			return execution.Verdict{}, instrumentedPath, fmt.Errorf("failed to write instrumented program: %w", werr)
		}
		return execution.Verdict{Status: status, Notes: append(notes, reason)}, instrumentedPath, nil
	}

	if unsupported := unsupportedProperties(checked); len(unsupported) > 0 {
		return stopEarly(execution.PropertyUnsupported,
			fmt.Sprintf("checking %s is not supported", joinProperties(unsupported)))
	}
	if parsed.Unsupported != "" {
		return stopEarly(execution.WitnessUnsupported, parsed.Unsupported)
	}

	instrumented, err := instrument.InstrumentWitness(programSrc, parsed, instrument.Options{
		RewriteReachError: property.Contains(checked, property.UnreachCall),
		Model:             options.model,
	})
	if err != nil {
		return execution.Verdict{}, "", fmt.Errorf("instrument: %w", err)
	}
	notes = append(notes, limitNotes(instrumented.Notes)...)

	// A program without nondeterministic calls needs no input values, so it
	// can be executed even if the witness provides none.
	if instrumented.InjectedSites == 0 && instrumented.NondetSites > 0 {
		return stopEarly(execution.WitnessUnsupported,
			fmt.Sprintf("witness provides no input values we can interpret (waypoints seen: %s)", parsed.Counts.Summary()))
	}

	if werr := os.WriteFile(instrumentedPath, []byte(instrumented.Source), 0o644); werr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("failed to write instrumented program: %w", werr)
	}

	harnessPath := filepath.Join(tempDir, "harness.c")
	if herr := harness.WriteHarnessFile(harnessPath); herr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("failed to write harness: %w", herr)
	}

	binary, cerr := execution.Compile(instrumented.Source, harnessPath,
		execution.CompileOptions{OutputDir: tempDir, Model: options.model, Properties: checked})
	if cerr != nil {
		return execution.Verdict{}, instrumentedPath, fmt.Errorf("compile: %w", cerr)
	}

	verdict, rerr := execution.Run(context.Background(), binary, options.timeout, checked)
	verdict.Notes = append(notes, verdict.Notes...)
	if rerr != nil {
		return verdict, instrumentedPath, fmt.Errorf("run: %w", rerr)
	}
	if verdict.Status == execution.Confirmed && verdict.Violated == property.NoOverflow &&
		execution.OverflowReportIsForRemainder(verdict.Stderr, instrumented.Source) {
		verdict.Status = execution.NotConfirmed
		verdict.Violated = ""
		verdict.Notes = append(verdict.Notes, "the reported overflow is in a remainder operation, which no-overflow does not cover")
	}
	checkTargetLocation(&verdict, parsed.Targets, strings.Split(programSrc, "\n"))
	return verdict, instrumentedPath, nil
}

// errorMessage formats an error for stderr as
// "witness2test-match error: <details>", or as
// "witness2test-match error [<tag>]: <details>" for an error with a tag.
// The BenchExec tool-info module shows a tagged error as "ERROR(<tag>)".
func errorMessage(err error) string {
	var tagged *taggedError
	if errors.As(err, &tagged) {
		return fmt.Sprintf("witness2test-match error [%s]: %v", tagged.tag, err)
	}
	return fmt.Sprintf("witness2test-match error: %v", err)
}

// Tags that name the cause of an error. A tag consists of lowercase letters,
// digits, spaces and '-', and starts with a letter.
const (
	// tagInvalidWitness marks an error in the witness, not in witness2test-match.
	tagInvalidWitness = "invalid witness"
)

// taggedError is an error whose cause is named by a tag.
type taggedError struct {
	tag string
	err error
}

func (e *taggedError) Error() string {
	return e.err.Error()
}

func (e *taggedError) Unwrap() error {
	return e.err
}

// describeEntryTypes lists the entry types of a witness. They are content of
// the witness and printed quoted.
func describeEntryTypes(entryTypes []string) string {
	if len(entryTypes) == 0 {
		return "no entries"
	}
	quoted := make([]string, len(entryTypes))
	for i, entryType := range entryTypes {
		quoted[i] = fmt.Sprintf("%q", entryType)
	}
	return strings.Join(quoted, ", ")
}

func effectiveModel(model string) string {
	if model == "" {
		return "LP64"
	}
	return model
}

func limitNotes(notes []string) []string {
	if len(notes) <= maxPrintedNotes {
		return notes
	}
	limited := append([]string{}, notes[:maxPrintedNotes]...)
	return append(limited, fmt.Sprintf("... and %d more waypoints that were not matched", len(notes)-maxPrintedNotes))
}

// checkTargetLocation withdraws a confirmation if the violation was observed
// outside the statement that the witness's target waypoint names. Only lines
// are compared: the violation must be observed on the target's line, or on a
// later line of the statement that starts there (see statementSpans). The
// check is skipped where the line of the violation cannot be determined,
// which includes valid-memtrack and valid-memcleanup.
func checkTargetLocation(verdict *execution.Verdict, targets []witness.Location, programLines []string) {
	if verdict.Status != execution.Confirmed || len(targets) == 0 {
		return
	}
	line, found := execution.ViolationLine(verdict.Violated, verdict.Stderr)
	if !found {
		if verdict.Violated != property.ValidMemtrack && verdict.Violated != property.ValidMemcleanup {
			verdict.Notes = append(verdict.Notes, "could not determine the line of the violation; the witness's target location was not checked")
		}
		return
	}
	targetLines := make([]string, len(targets))
	for i, target := range targets {
		if statementSpans(programLines, target.Line, line) {
			return
		}
		targetLines[i] = fmt.Sprint(target.Line)
	}
	verdict.Notes = append(verdict.Notes, fmt.Sprintf("violation of %s observed at line %d, but the witness's target is at line %s",
		verdict.Violated, line, strings.Join(targetLines, ", ")))
	verdict.Status = execution.NotConfirmed
	verdict.Violated = ""
}

// statementSpans reports whether a statement that starts on line from (1-based)
// can extend to line to: that is, from <= to and none of the lines from
// .. to-1 contains a ';', '{' or '}', which would end the statement. The test
// is textual and errs on the side of "no": such a character inside a string,
// a comment or a for header also counts.
func statementSpans(lines []string, from, to int) bool {
	if from < 1 || to > len(lines) || from > to {
		return false
	}
	for line := from; line < to; line++ {
		if strings.ContainsAny(lines[line-1], ";{}") {
			return false
		}
	}
	return true
}

func formatVerdict(v execution.Verdict, instrumentedPath string) string {
	status := string(v.Status)
	if v.Status == execution.Confirmed {
		status += " " + v.Violated.Name()
	}
	msg := fmt.Sprintf("Verdict: %s (exit code %d). Instrumented program: %s",
		status, v.ExitCode, instrumentedPath)
	for _, note := range v.Notes {
		msg += "\nNote: " + note
	}
	if v.Stderr != "" {
		msg += "\n--- program stderr ---\n" + v.Stderr
	}
	return msg
}
