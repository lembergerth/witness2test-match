<!--
This file is part of witness2test-match,
a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
https://github.com/lembergerth/witness2test-match

SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>

SPDX-License-Identifier: Apache-2.0
-->
# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`witness2test-match` turns SV-COMP violation witnesses (YAML format v2) into executable C tests that reproduce the witnessed violation. It is the dual of
[test-to-witness](https://gitlab.com/sosy-lab/software/test-to-witness): given a
C program and a v2 violation witness, it extracts the nondeterministic input
values the witness states and instruments the program so each matched
`__VERIFIER_nondet_X()` call site is replaced by a location-stamped injection
function that returns the witness values in order. The instrumented program is
compiled against a small embedded C harness, with sanitizers selected by the
property the witness claims, and executed. Exit code plus the report on stderr
tell which property was violated.

## Key Architecture

- **Main package** (`witness2test.go`): CLI entry point and pipeline orchestration; decides which properties are checked and applies the target-location check.
- **`property/`**: the SV-COMP properties; parses property files (`CHECK(...)` lines) and witness specifications (also bare formulas like `G ! overflow`).
- **`witness/`**: parses v2 violation witnesses (YAML): specification, `function_return` / `assumption` / `branching` / `target` waypoints. Validates literal values against a strict allowlist (security).
- **`instrument/`**: rewrites C source — matches waypoints to `__VERIFIER_nondet_X()` call sites (three strategies, see README "Where Input Values Come From"), renames matched sites to `__VERIFIER_nondet_value_injection_<line>_<col>()`, prepends one C definition per site, and optionally redirects `reach_error()` calls. Text-based, no C parser.
- **`harness/`**: embedded C harness: weak `reach_error()` and `__VERIFIER_nondet_*` defaults; under `W2T_CHECK_MEMCLEANUP` the allocation-counting wrappers for valid-memcleanup; under `W2T_CHECK_MEMTRACK` the search that exempts blocks referenced only by a pointer to their end from the leak check.
- **`execution/`**: compiles with per-property flags (`properties.go`), runs with a timeout, classifies exit code + stderr into a verdict (`classify`), and extracts the line of a violation from sanitizer output (`location.go`).
- **`internal/exitcodes/`**: single source of truth for the exit codes used by the harness, the generated code, the sanitizer configuration, and the verdict logic.

Pipeline:

1. Read witness and program; parse the witness (no `violation_sequence` entry → error).
2. Checked properties = properties the witness claims; they must be a subset of the `--property` selection (error otherwise). No or unknown specification → the selection is checked.
3. Claimed property not checkable (`no-data-race`) → verdict `PropertyUnsupported`, stop.
4. Instrument. Program has nondet calls but no witness value matched → verdict `WitnessUnsupported`, stop. A program without nondet calls is executed anyway.
5. Write `output/instrumented_program.c`; compile with the harness and the flags for the checked properties.
6. Execute with timeout (process-group kill on timeout).
7. Classify: a violation is confirmed only if it violates a checked property.
8. A no-overflow report for `INT_MIN % -1` is withdrawn (remainder is not covered).
9. Target check: for unreach-call, no-overflow, valid-free, valid-deref the violation must be observed on the target waypoint's line or a later line of the statement starting there (`statementSpans`).

## Build and Development Commands

```bash
make build              # build bin/witness2test-match with version info from git
make test               # run unit tests
make integration-test   # build, then run ./integration-test.sh
make lint               # golangci-lint
make deps               # go mod tidy
```

### Running the tool

```bash
bin/witness2test-match --witness path/to/witness.yml --program path/to/program.c --output output/
```

Options:

- `--witness <path>` (required)
- `--program <path>` (required)
- `--property <path>`     — property file; default property `unreach-call`
- `--model ILP32|LP64`    — default `LP64`
- `--output <dir>`        — default `output`
- `--time-per-run <sec>`  — default 60
- `--version`

## Implementation Notes

- **Test-driven development**: write the failing test first, then the implementation.
- **Position numbering**: all line and column values in the public API of `instrument/` and `witness/` are **1-based**. A column of 0 means "not given in the witness".
- **Physical lines**: witness locations refer to physical lines of the input file. The program is fed to gcc on stdin after the generated definitions and a `#line 1`; linemarkers and `#line` directives inside the program are blanked out. Sanitizer reports therefore name physical lines under the file name `<stdin>`; `execution.ViolationLine` relies on this.
- **Exit codes** (`internal/exitcodes/exitcodes.go`): 213 `reach_error()` reached, 214 witness inconsistent (more calls than values), 215 sanitizer report (set via `ASAN_OPTIONS`/`UBSAN_OPTIONS`/`LSAN_OPTIONS`), 216 memcleanup violation. An exit code alone never confirms a violation; the matching report (for 213: the `reach_error called` message) must be on stderr.
- **Sanitizer classification** (`execution/properties.go`): no-overflow counts only "cannot be represented in type" reports (minus `INT_MIN % -1`, recognized by the operator at the reported position); address-sanitizer error kinds map to valid-free or valid-deref via `asanKinds`; unknown kinds (stack exhaustion, overlapping `memcpy`) confirm nothing. `reach_error()` is only redirected when unreach-call is checked.
- **Requirements for tests**: gcc with sanitizer runtimes; 32-bit cases need `gcc-multilib` and the 32-bit sanitizer runtimes and skip otherwise.
- **Constraint allowlist** (security-critical, `witness/witness.go`): every value taken from a witness and embedded in generated C must match a strict regex for integer / float / character / boolean literals. Without this allowlist, an attacker-controlled witness could inject arbitrary C into the generated source.
- **Short-circuit conditions**: a branching waypoint on a condition that combines a nondet call with `&&`/`||` is deliberately not used — the witness does not say which operand decided the outcome.
- **Sandbox limits**: the tool runs the compiled binary with a wall-clock timeout and process-group kill on timeout. It does *not* apply `setrlimit` or namespacing. On shared infrastructure, wrap invocations in `bwrap` or `firejail`.
- **Leniency**: only an unparsable witness (or one without `violation_sequence`, or a claim outside the `--property` selection) is an error. Waypoints that cannot be used (including `function_return` on a non-nondet call) become notes; at most 10 are printed.
- **`reach_error()` redirection** passes `__LINE__`, so a call inside a macro is reported at the line where the macro is used. Both the generated wrapper and the harness's weak `reach_error()` print `witness2test-match: reach_error called`.
- **valid-memtrack and stale pointers**: the leak sanitizer treats every word on the live stack as a possible pointer. Harness code that handles block addresses at exit must keep them out of scanned memory (store them inverted, scrub the stack afterwards, see `harness.c.template`); otherwise real leaks are hidden.
- **Checks before finishing**: `gofmt -l .`, `go vet ./...`, `make test`, `make integration-test`, `make archive-test`, `make lint`, `reuse lint`.
- **No multi-line nondet calls**: a `__VERIFIER_nondet_X(\n)` expression split across multiple lines is not recognized.

## File Handling

- Do not handle calls to `Close()` if the file was only read.
