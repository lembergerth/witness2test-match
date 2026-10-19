# Property selection and confirmation output

Accept an optional `--property <file>` and retain every selected property in file
order. Default to `unreach-call` when the option is omitted. A confirmed execution
prints `Verdict: Confirmed <first property>` followed by the existing exit code
and instrumented-program path. Actual checking remains unchanged.

## Domain model and matching

Each nonblank line must match one complete CHECK expression anchored at both
ends. Ignore blank lines, retain duplicates, and reject an empty file or any
unrecognized line. Report the offending line number. Reading a missing or
unreadable file fails before program instrumentation.

Use escaped regular-expression parentheses. Allow arbitrary whitespace around
syntactic punctuation and between CHECK, init, main, and LTL and their opening
parentheses. Within the LTL formula, follow the user's example: require one or
more whitespace characters between G and its operand, and between ! and its
operand; allow arbitrary whitespace around call/reach_error parentheses. Never
allow whitespace within identifiers or compound property names. Match one
expression per line; accept CRLF and a final line without a newline.

The property names are `unreach-call`, `valid-memsafety(valid-free)`,
`valid-memsafety(valid-deref)`, `valid-memsafety(valid-memtrack)`, `no-overflow`,
`no-data-race`, and `valid-memcleanup`, corresponding to the seven requested
formulas. The LTL formulas map as follows, each within
`CHECK( init(main()), LTL(<formula>) )`:

| Formula | Property |
| --- | --- |
| `G ! call(reach_error())` | `unreach-call` |
| `G valid-free` | `valid-memsafety(valid-free)` |
| `G valid-deref` | `valid-memsafety(valid-deref)` |
| `G valid-memtrack` | `valid-memsafety(valid-memtrack)` |
| `G ! overflow` | `no-overflow` |
| `G ! data-race` | `no-data-race` |
| `G valid-memcleanup` | `valid-memcleanup` |

Parse the full CHECK envelope, including init(main()), rather than searching for
property-name substrings.

## Technical design

Add property parsing to the main package in `properties.go`, using a string-based
Property type and an ordered slice. Keep parsing pure and read the property file
at the CLI boundary. Keep execution statuses independent of selected properties.
Pass the selected properties to verdict formatting, which uses the first only
for Confirmed. All other verdicts retain their existing text.

## Work packages

### WP-1: Parse selected properties

- Deliverable: pure parser and tests in `properties.go` and `properties_test.go`.
- Acceptance: recognize all seven formulas, preserve order and duplicates,
  accept documented whitespace, reject malformed or unknown expressions,
  reject empty input, and report line numbers.
- Dependencies: none.
- Risks: low impact on existing code; moderate regex escaping risk; essential
  to accurate property selection.
- [x] Implement and test the parser; commit it as a new unit.
- Implementation context: read the matching rules above and existing Go test
  conventions. Use the standard regexp and strings libraries. Assert complete
  property slices and complete error messages.

### WP-2: Connect CLI selection and verdict output

- Deliverable: `--property` support and updated formatting in `witness2test.go`,
  with tests in `witness2test_test.go` and `witness2test_integration_test.go`.
- Acceptance: default invocation confirms unreach-call; explicit file selection
  confirms its first property, including a non-unreach property; later selected
  properties remain available in the parsed slice; other verdicts are unchanged;
  missing, empty, and invalid property files fail clearly. Test the actual binary
  with explicit multiple properties and the default invocation.
- Dependencies: WP-1.
- Risks: changes the Confirmed output intentionally; low implementation
  complexity; essential user-facing wiring. Existing invocation flags and the
  execution pipeline remain compatible.
- [x] Implement CLI wiring and full-output tests; update README.adoc usage,
  matching rules, supported names, and temporary first-property behavior.
- [x] Run Go tests, lint, build, and integration tests; commit the wiring.
- Implementation context: read run and formatVerdict in witness2test.go and the
  existing pipeline tests. Keep file reading at the CLI boundary. Capture output
  in a temporary file and compare the complete expected verdict line.

## Review

Plan review covers consistency, security, verification coverage, devil's
advocate, and simplicity. Work packages run sequentially; review agents inspect
only this design. Implementation stays in the current checkout.

All five review lenses report no findings after recording the exact formula
mapping. Baseline Go tests pass. The installed golangci-lint 1.64.8 reports
"no go files to analyze" while loading packages with the available Go 1.26
toolchain, so lint remains an environment limitation.

Completed validation: `go test ./...`, `go vet ./...`, `make integration-test`
(three passing cases), and `git diff --check`. Binary tests assert complete
confirmation output for all seven properties, default selection, and two
opposite property orders. Parser tests cover whitespace, CRLF, blank lines,
duplicates, malformed expressions, and empty files. CLI tests cover missing and
invalid property files before output directory creation.
