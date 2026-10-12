# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`witness2test` turns SV-COMP violation witnesses (YAML format v2) into executable C tests that reproduce the witnessed violation. It is the dual of
[test-to-witness](https://gitlab.com/sosy-lab/software/test-to-witness): given a
C program and a v2 violation witness, it extracts the nondeterministic input
values implied by the witness's `function_return` waypoints and instruments the
program so each matched `__VERIFIER_nondet_X()` call site is replaced by a
location-stamped injection function that returns the witness values in order.
The instrumented program is compiled against a small embedded C harness and
executed; reaching the witnessed `reach_error()` point is observable as a
specific exit code.

## Key Architecture

The codebase is organized into several packages:

- **Main package** (`witness2test.go`): CLI entry point and pipeline orchestration.
- **`witness/`**: parses v2 violation witnesses (YAML) and extracts injection points (`function_return` waypoints with `\result == <literal>` constraints). Validates literal values against a strict allowlist (security).
- **`instrument/`**: rewrites C source — renames witnessed `__VERIFIER_nondet_X()` call sites to `__VERIFIER_nondet_value_injection_<line>_<col>()` and prepends one C definition per witnessed site. Regex-based, single-line.
- **`harness/`**: embedded C harness that provides `reach_error()` (exits with `exitcodes.ViolationReached`) and weak default `__VERIFIER_nondet_*` implementations so unwitnessed sites link.
- **`execution/`**: compiles and executes the instrumented program with a timeout; converts the exit code into a verdict.
- **`internal/exitcodes/`**: single source of truth for the exit codes used by the harness and the generated injection function.
- **`testutils/`**: shared testing utilities.

Pipeline:

1. Read witness and program.
2. Parse witness → ordered injection points (filtered to `function_return` / `action: follow` / literal `\result == <V>`).
3. Empty extraction → verdict `WitnessUnsupported`.
4. Collect nondet call sites in source.
5. Match witness locations to call sites (mismatch → error).
6. Instrument source; write `output/instrumented_program.c`.
7. Compile with embedded harness.
8. Execute with timeout (process-group kill on timeout).
9. Verdict from exit code via `internal/exitcodes`.

## Build and Development Commands

```bash
make build              # build bin/witness2test with version info from git
make test               # run unit tests
make integration-test   # build, then run ./integration-test.sh
make lint               # golangci-lint
make deps               # go mod tidy
```

### Running the tool

```bash
bin/witness2test --witness path/to/witness.yml --program path/to/program.c --output output/
```

Options:

- `--witness <path>` (required)
- `--program <path>` (required)
- `--output <dir>`        — default `output`
- `--time-per-run <sec>`  — default 60
- `--version`

## Implementation Notes

- **Position numbering**: all line and column values in the public API of `instrument/` and `witness/` are **1-based**. The internal byte-offset bookkeeping that mirrors `test-to-witness` uses 0-based offsets, converted to 1-based at the package boundary.
- **Column convention**: v1 assumes the Symbiotic-style closing-paren column for `function_return` waypoints. Mismatching witnesses produce an explicit "no call site at (line, col)" diagnostic.
- **Exit codes** (`internal/exitcodes/exitcodes.go`):
  - `ViolationReached = 213` — emitted from the harness's `reach_error()`.
  - `WitnessInconsistent = 214` — emitted from the generated injection function's overflow branch.
  - Unusual values are chosen to minimize collision with `exit()` calls a benchmark program might make on its own.
- **Constraint allowlist** (security-critical, `witness/witness.go`): every `\result == <V>` extracted from the witness must match a strict regex for integer / float / character / boolean literals. Anything else is rejected. Without this allowlist, an attacker-controlled witness could inject arbitrary C into the generated source.
- **Sandbox limits**: the tool runs the compiled binary with a wall-clock timeout and process-group kill on timeout. It does *not* apply `setrlimit` or namespacing. On shared infrastructure, wrap invocations in `bwrap` or `firejail`.
- **No multi-line nondet calls**: a `__VERIFIER_nondet_X(\n)` expression split across multiple lines is not recognized by the regex.
- **`assumption` waypoints are not interpreted**: a witness carrying nondet values only via `assumption` constraints yields the verdict `WitnessUnsupported` (distinct from `NotConfirmed`).

## File Handling

- Do not handle calls to `Close()` if the file was only read.
