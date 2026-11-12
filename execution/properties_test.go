// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package execution

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"witness2test/harness"
	"witness2test/property"
)

// requireModel skips the test if gcc cannot build and run sanitized programs
// for the given data model (e.g. missing 32-bit sanitizer runtimes).
func requireModel(t *testing.T, model string) {
	t.Helper()
	requireGCC(t)
	if model != "ILP32" {
		return
	}
	dir := t.TempDir()
	cmd := exec.Command("gcc", "-m32", "-fsanitize=address", "-x", "c", "-", "-o", filepath.Join(dir, "probe"))
	cmd.Stdin = strings.NewReader("int main(void){return 0;}\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("32-bit sanitizer build not available: %v\n%s", err, out)
	}
}

func runWithProperties(t *testing.T, model, programCode string, properties []property.Property) Verdict {
	t.Helper()
	requireModel(t, model)
	dir := t.TempDir()
	harnessPath := filepath.Join(dir, "harness.c")
	if err := harness.WriteHarnessFile(harnessPath); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary, err := Compile(programCode, harnessPath, CompileOptions{OutputDir: dir, Model: model, Properties: properties})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	v, err := Run(context.Background(), binary, 20*time.Second, properties)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return v
}

type propertyCase struct {
	name     string
	program  string
	violated property.Property // empty: NotConfirmed expected
}

func checkPropertyCases(t *testing.T, properties []property.Property, cases []propertyCase) {
	t.Helper()
	for _, model := range []string{"LP64", "ILP32"} {
		for _, tt := range cases {
			t.Run(model+"/"+tt.name, func(t *testing.T) {
				v := runWithProperties(t, model, tt.program, properties)
				wantStatus := NotConfirmed
				if tt.violated != "" {
					wantStatus = Confirmed
				}
				if v.Status != wantStatus || v.Violated != tt.violated {
					t.Errorf("got %s %q (exit code %d), want %s %q\nstderr: %s", v.Status, v.Violated, v.ExitCode, wantStatus, tt.violated, v.Stderr)
				}
			})
		}
	}
}

const overflowPrelude = `#include <limits.h>
#include <stdlib.h>
volatile int max = INT_MAX, min = INT_MIN, one = 1, minusOne = -1;
`

func TestNoOverflow(t *testing.T) {
	checkPropertyCases(t, []property.Property{property.NoOverflow}, []propertyCase{
		{"addition", overflowPrelude + "int main(void){ int r = max + one; return r == 0; }\n", property.NoOverflow},
		{"subtraction", overflowPrelude + "int main(void){ int r = min - one; return r == 0; }\n", property.NoOverflow},
		{"multiplication", overflowPrelude + "int main(void){ int r = max * 2; return r == 0; }\n", property.NoOverflow},
		{"negation", overflowPrelude + "int main(void){ int r = -min; return r == 0; }\n", property.NoOverflow},
		{"division", overflowPrelude + "int main(void){ int r = min / minusOne; return r == 0; }\n", property.NoOverflow},
		{"left shift", overflowPrelude + "int main(void){ int r = one << 31; return r == 0; }\n", property.NoOverflow},
		{"long long addition", overflowPrelude + "int main(void){ volatile long long big = LLONG_MAX; long long r = big + one; return r == 0; }\n", property.NoOverflow},

		{"no overflow", overflowPrelude + "int main(void){ int r = max - one; return r == 0; }\n", ""},
		{"unsigned wraparound", overflowPrelude + "int main(void){ volatile unsigned u = UINT_MAX; unsigned r = u + 1u; return r != 0; }\n", ""},
		{"conversion from double", overflowPrelude + "int main(void){ volatile double d = 1e30; int r = (int)d; return r == 12345; }\n", ""},
		{"narrowing conversion", overflowPrelude + "int main(void){ volatile short s = SHRT_MAX; s = s + 1; return 0; }\n", ""},
		{"abs of INT_MIN", overflowPrelude + "int main(void){ int r = abs(min); return r == 12345; }\n", ""},
		{"labs of LONG_MIN", overflowPrelude + "int main(void){ volatile long m = LONG_MIN; long r = labs(m); return r == 12345; }\n", ""},
		{"llabs of LLONG_MIN", overflowPrelude + "int main(void){ volatile long long m = LLONG_MIN; long long r = llabs(m); return r == 12345; }\n", ""},
		{"imaxabs of INTMAX_MIN", "#include <inttypes.h>\n" + overflowPrelude + "int main(void){ volatile intmax_t m = INTMAX_MIN; intmax_t r = imaxabs(m); return r == 12345; }\n", ""},
		{"left shift of negative value", overflowPrelude + "int main(void){ int r = minusOne << one; return r == 12345; }\n", ""},
		{"shift exponent too large", overflowPrelude + "int main(void){ volatile int e = 40; int r = one << e; return r == 12345; }\n", ""},
		// Undefined behavior that is no overflow must not end the test early.
		{"overflow after too large shift exponent", overflowPrelude + "int main(void){ volatile int e = 40; int r = one << e; r = max + one; return r == 12345; }\n", property.NoOverflow},
		{"overflow after unsigned wraparound", overflowPrelude + "int main(void){ volatile unsigned u = 0; unsigned w = u - 1u; int r = max + (int)(w != 0); return r == 12345; }\n", property.NoOverflow},
		{"right shift", overflowPrelude + "int main(void){ int r = max >> one; return r == 12345; }\n", ""},
	})
}

const memPrelude = `#include <stdlib.h>
#include <string.h>
volatile int two = 2;
int global[2];
int *keep;
`

func TestMemsafety(t *testing.T) {
	checkPropertyCases(t, memsafety, []propertyCase{
		{"double free", memPrelude + "int main(void){ int *p = malloc(8); free(p); free(p); return 0; }\n", property.ValidFree},
		{"free of stack memory", memPrelude + "int main(void){ int local[2]; int *p = local; free(p); return 0; }\n", property.ValidFree},
		{"free of offset pointer", memPrelude + "int main(void){ int *p = malloc(8); free(p + 1); return 0; }\n", property.ValidFree},
		{"free of alloca memory", memPrelude + "int main(void){ int *p = __builtin_alloca(8); free(p); return 0; }\n", property.ValidFree},

		{"use after free", memPrelude + "int main(void){ int *p = malloc(8); free(p); return p[0]; }\n", property.ValidDeref},
		{"heap out of bounds", memPrelude + "int main(void){ int *p = malloc(8); int r = p[two]; free(p); return r; }\n", property.ValidDeref},
		{"stack out of bounds", memPrelude + "int main(void){ int local[2]; local[0] = 0; return local[two]; }\n", property.ValidDeref},
		{"global out of bounds", memPrelude + "int main(void){ return global[two]; }\n", property.ValidDeref},
		{"null dereference", memPrelude + "int main(void){ int * volatile p = 0; return *p; }\n", property.ValidDeref},
		{"use after return", memPrelude + "int *f(void){ int x = 1; int * volatile p = &x; return p; }\nint main(void){ return *f(); }\n", property.ValidDeref},
		{"use after scope", memPrelude + "int main(void){ int * volatile p; { int x = 1; p = &x; } return *p; }\n", property.ValidDeref},
		{"variable-length array out of bounds", memPrelude + "int main(void){ volatile int n = 2; int vla[n]; vla[0] = 0; return vla[n + two]; }\n", property.ValidDeref},
		{"out of bounds in memcpy", memPrelude + "int main(void){ char *p = malloc(4); char src[8] = {0}; memcpy(p, src, 4 * two); free(p); return 0; }\n", property.ValidDeref},

		{"lost pointer", memPrelude + "int main(void){ int *p = malloc(8); p = 0; return p != 0; }\n", property.ValidMemtrack},
		{"local pointer at return of main", memPrelude + "int main(void){ int *p = malloc(8); p[0] = 1; return 0; }\n", property.ValidMemtrack},

		// A pointer to the first address after a block keeps the block tracked.
		{"only pointer is one past the end, in a global", memPrelude + "int main(void){ int *p = malloc(4 * sizeof(int)); for (int i = 0; i < 4; i++) { *p = i; p++; } keep = p; return 0; }\n", ""},
		{"only pointer is one past the end, in a tracked block", memPrelude + "int **holder;\nint main(void){ holder = malloc(sizeof(int *)); int *p = malloc(4 * sizeof(int)); *holder = p + 4; p = 0; return p != 0; }\n", ""},
		{"only pointer is one past the end, in a live local at exit", memPrelude + "int main(void){ char *p = malloc(3); char * volatile end = p + 3; p = 0; exit(end == 0); }\n", ""},
		{"one past the end of another block does not track a lost block", memPrelude + "int main(void){ int *p = malloc(4 * sizeof(int)); int *lost = malloc(sizeof(int)); keep = p + 4; lost = 0; return lost != 0; }\n", property.ValidMemtrack},
		{"lost after realloc moved the end", memPrelude + "int main(void){ int *p = malloc(4 * sizeof(int)); keep = p + 4; p = realloc(p, 4000 * sizeof(int)); p = 0; return p != 0; }\n", property.ValidMemtrack},
		{"memory kept in packed global struct", memPrelude + "struct __attribute__((packed)) rec { char tag; int *data; } packed;\nint main(void){ packed.data = malloc(8); return 0; }\n", ""},
		{"memory kept in global", memPrelude + "int main(void){ keep = malloc(8); return 0; }\n", ""},
		{"all freed", memPrelude + "int main(void){ int *p = malloc(8); p[1] = 1; free(p); return 0; }\n", ""},
		{"free of null", memPrelude + "int main(void){ free(0); return 0; }\n", ""},
	})
}

func TestMemsafetySubsetOfProperties(t *testing.T) {
	doubleFree := memPrelude + "int main(void){ int *p = malloc(8); free(p); free(p); return 0; }\n"
	leak := memPrelude + "int main(void){ int *p = malloc(8); p = 0; return p != 0; }\n"
	checkPropertyCases(t, []property.Property{property.ValidDeref}, []propertyCase{
		{"double free is not a deref violation", doubleFree, ""},
		{"leak is not checked", leak, ""},
	})
	checkPropertyCases(t, []property.Property{property.ValidMemtrack}, []propertyCase{
		{"leak", leak, property.ValidMemtrack},
		{"double free is not a memtrack violation", doubleFree, ""},
	})
}

const cleanupPrelude = `#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int *keep;
`

func TestMemcleanup(t *testing.T) {
	checkPropertyCases(t, []property.Property{property.ValidMemcleanup}, []propertyCase{
		{"memory kept in global at return", cleanupPrelude + "int main(void){ keep = malloc(8); return 0; }\n", property.ValidMemcleanup},
		{"memory kept at exit", cleanupPrelude + "int main(void){ keep = malloc(8); exit(0); }\n", property.ValidMemcleanup},
		{"memory kept at abort", cleanupPrelude + "int main(void){ keep = malloc(8); abort(); }\n", property.ValidMemcleanup},
		{"memory kept at _Exit", cleanupPrelude + "int main(void){ keep = malloc(8); _Exit(1); }\n", property.ValidMemcleanup},
		{"memory kept at _exit", cleanupPrelude + "#include <unistd.h>\nint main(void){ keep = malloc(8); _exit(1); }\n", property.ValidMemcleanup},
		{"memory kept at failed assertion", cleanupPrelude + "#include <assert.h>\nvolatile int zero = 0;\nint main(void){ keep = malloc(8); assert(zero); return 0; }\n", property.ValidMemcleanup},
		{"calloc not freed", cleanupPrelude + "int main(void){ keep = calloc(2, 4); return 0; }\n", property.ValidMemcleanup},
		{"realloc result not freed", cleanupPrelude + "int main(void){ keep = malloc(8); keep = realloc(keep, 64); return 0; }\n", property.ValidMemcleanup},
		{"strdup not freed", cleanupPrelude + "char *s;\nint main(void){ s = strdup(\"x\"); return 0; }\n", property.ValidMemcleanup},

		{"realloc of null not freed", cleanupPrelude + "int main(void){ keep = realloc(0, 8); return 0; }\n", property.ValidMemcleanup},
		{"aligned_alloc not freed", cleanupPrelude + "int main(void){ keep = aligned_alloc(16, 32); return 0; }\n", property.ValidMemcleanup},
		{"posix_memalign not freed", cleanupPrelude + "int main(void){ void *p = 0; if (posix_memalign(&p, 16, 32)) return 0; keep = p; return 0; }\n", property.ValidMemcleanup},
		{"reallocarray of null not freed", "#define _GNU_SOURCE\n" + cleanupPrelude + "int main(void){ keep = reallocarray(0, 4, 4); return 0; }\n", property.ValidMemcleanup},
		{"one of two blocks freed", cleanupPrelude + "int main(void){ keep = malloc(8); int *other = malloc(8); free(other); return 0; }\n", property.ValidMemcleanup},
		{"second block kept after free of null", cleanupPrelude + "int main(void){ free(0); keep = malloc(8); return 0; }\n", property.ValidMemcleanup},

		{"realloc to size zero frees", cleanupPrelude + "int main(void){ keep = malloc(8); keep = realloc(keep, 0); free(keep); return 0; }\n", ""},
		{"reallocarray to size zero frees", "#define _GNU_SOURCE\n" + cleanupPrelude + "int main(void){ keep = malloc(8); keep = reallocarray(keep, 0, 1); free(keep); return 0; }\n", ""},
		{"aligned_alloc and posix_memalign freed", cleanupPrelude + "int main(void){ void *p = 0; keep = aligned_alloc(16, 32); if (posix_memalign(&p, 16, 32)) return 0; free(p); free(keep); return 0; }\n", ""},
		{"freed in destructor", cleanupPrelude + "__attribute__((destructor)) static void cleanup(void){ free(keep); }\nint main(void){ keep = malloc(8); return 0; }\n", ""},
		{"freed in exit handler", cleanupPrelude + "static void cleanup(void){ free(keep); }\nint main(void){ keep = malloc(8); atexit(cleanup); exit(0); }\n", ""},
		{"threads allocate and free concurrently", cleanupPrelude + "#include <pthread.h>\nstatic void *work(void *arg){ for (int i = 0; i < 200000; i++) { void *p = malloc(8); free(p); } return arg; }\nint main(void){ pthread_t t[4]; for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, work, 0); for (int i = 0; i < 4; i++) pthread_join(t[i], 0); return 0; }\n", ""},
		{"all freed", cleanupPrelude + "int main(void){ keep = malloc(8); keep = realloc(keep, 64); free(keep); return 0; }\n", ""},
		{"all freed with output", cleanupPrelude + "int main(void){ keep = malloc(8); printf(\"hello\\n\"); free(keep); return 0; }\n", ""},
		{"all freed before abort", cleanupPrelude + "int main(void){ keep = malloc(8); free(keep); abort(); }\n", ""},
		{"all freed before _Exit", cleanupPrelude + "int main(void){ keep = malloc(8); free(keep); _Exit(1); }\n", ""},
		{"all freed before failed assertion", cleanupPrelude + "#include <assert.h>\nvolatile int zero = 0;\nint main(void){ keep = malloc(8); free(keep); assert(zero); return 0; }\n", ""},
		{"free of null after free", cleanupPrelude + "int main(void){ keep = malloc(8); free(keep); keep = 0; free(keep); return 0; }\n", ""},
		{"no allocation", cleanupPrelude + "int main(void){ return 3; }\n", ""},
		{"memory kept, program defines write", cleanupPrelude + programWrite + "int main(void){ keep = malloc(8); return 0; }\n", property.ValidMemcleanup},
	})
}

// SV-COMP programs (busybox, coreutils) define write() as a stub, which must
// not swallow the reports of the harness.
const programWrite = "long write(int fd, const void *buf, unsigned long n){ return 0; }\n"

func TestUnreachCallWithProgramWrite(t *testing.T) {
	program := "void reach_error(void);\n" + programWrite + "int main(void){ reach_error(); return 0; }\n"
	checkPropertyCases(t, []property.Property{property.UnreachCall}, []propertyCase{{"harness reach_error", program, property.UnreachCall}})
}

func TestUnreachCallOnlyWhenSelected(t *testing.T) {
	program := "void reach_error(void);\nint main(void){ reach_error(); return 0; }\n"
	checkPropertyCases(t, []property.Property{property.UnreachCall}, []propertyCase{{"selected", program, property.UnreachCall}})
	checkPropertyCases(t, []property.Property{property.NoOverflow}, []propertyCase{{"not selected", program, ""}})
}

// A violation is only confirmed with complete witness values: a nondet call
// without a witness value stops the test before the violation.
func TestNondetCallWithoutWitnessValue(t *testing.T) {
	program := "extern int __VERIFIER_nondet_int(void);\nvoid reach_error(void);\nint main(void){ if (__VERIFIER_nondet_int() == 0) reach_error(); return 0; }\n"
	for _, model := range []string{"LP64", "ILP32"} {
		t.Run(model, func(t *testing.T) {
			v := runWithProperties(t, model, program, []property.Property{property.UnreachCall})
			wantStderr := "witness2test-match: nondet call without witness value: __VERIFIER_nondet_int\n"
			if v.Status != Inconsistent || v.Stderr != wantStderr {
				t.Errorf("got %s (exit code %d), stderr %q; want WitnessInconsistent, stderr %q", v.Status, v.ExitCode, v.Stderr, wantStderr)
			}
		})
	}
}

// The exit codes by which the test reports its own outcome must pass the
// memcleanup check untouched.
func TestMemcleanupKeepsToolExitCodes(t *testing.T) {
	program := cleanupPrelude + "int main(void){ keep = malloc(8); _Exit(214); }\n"
	v := runWithProperties(t, "LP64", program, []property.Property{property.ValidMemcleanup})
	if v.Status != Inconsistent {
		t.Errorf("got %s (exit code %d), want WitnessInconsistent", v.Status, v.ExitCode)
	}
}

func TestSanitizerEnvironment(t *testing.T) {
	joined := strings.Join(sanitizerEnvironment(memsafety), " ")
	// Pointers stored unaligned (packed structs) still reference their block.
	for _, want := range []string{"detect_leaks=1", "use_unaligned=1", "exitcode=215"} {
		if !strings.Contains(joined, want) {
			t.Errorf("environment %q lacks %s", joined, want)
		}
	}
	if joined := strings.Join(sanitizerEnvironment([]property.Property{property.ValidDeref}), " "); !strings.Contains(joined, "detect_leaks=0") {
		t.Errorf("leak detection must be off unless valid-memtrack is checked: %q", joined)
	}
}

// The undefined-behavior sanitizer reports INT_MIN % -1 with the words it
// uses for INT_MIN / -1, but the remainder is not an operation that
// no-overflow covers.
func TestOverflowReportIsForRemainder(t *testing.T) {
	definitions := "/* generated */\nint f(void);\n#line 1\n"
	program := "volatile int a = -2147483647 - 1, b = -1;\nint main(void){\n  int q = 0;\n  q = a % b;\n  q = a / b;\n  return q;\n}\n"
	for _, tt := range []struct {
		name   string
		source string
		stderr string
		want   bool
	}{
		{"remainder", definitions + program, "<stdin>:4:9: runtime error: division of -2147483648 by -1 cannot be represented in type 'int'\n", true},
		{"division", definitions + program, "<stdin>:5:9: runtime error: division of -2147483648 by -1 cannot be represented in type 'int'\n", false},
		{"remainder without generated definitions", program, "<stdin>:4:9: runtime error: division of -2147483648 by -1 cannot be represented in type 'int'\n", true},
		{"other overflow", definitions + program, "<stdin>:4:9: runtime error: signed integer overflow: 1 + 2 cannot be represented in type 'int'\n", false},
		{"location outside the program", definitions + program, "<stdin>:99:9: runtime error: division of -2147483648 by -1 cannot be represented in type 'int'\n", false},
		{"no report", definitions + program, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := OverflowReportIsForRemainder(tt.stderr, tt.source); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemainderReportOnRealProgram(t *testing.T) {
	program := "volatile int a = -2147483647 - 1, b = -1;\nint main(void){\n  int q = 0;\n  q = a % b;\n  return q;\n}\n"
	for _, model := range []string{"LP64", "ILP32"} {
		t.Run(model, func(t *testing.T) {
			v := runWithProperties(t, model, program, []property.Property{property.NoOverflow})
			if !OverflowReportIsForRemainder(v.Stderr, program) {
				t.Errorf("remainder not recognized in: %s", v.Stderr)
			}
		})
	}
}
