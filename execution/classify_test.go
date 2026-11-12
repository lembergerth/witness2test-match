// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package execution

import (
	"testing"

	"witness2test/internal/exitcodes"
	"witness2test/property"
)

var memsafety = []property.Property{property.ValidFree, property.ValidDeref, property.ValidMemtrack}

func TestClassify(t *testing.T) {
	const san = exitcodes.SanitizerReport
	tests := []struct {
		name       string
		exitCode   int
		stderr     string
		properties []property.Property
		status     VerdictStatus
		violated   property.Property
	}{
		{"reach_error", exitcodes.ViolationReached, "witness2test-match: reach_error called at line 5\n", []property.Property{property.UnreachCall}, Confirmed, property.UnreachCall},
		{"reach_error of harness", exitcodes.ViolationReached, reachErrorMarker + "\n", []property.Property{property.UnreachCall}, Confirmed, property.UnreachCall},
		{"exit code of reach_error without its message", exitcodes.ViolationReached, "", []property.Property{property.UnreachCall}, NotConfirmed, ""},
		{"reach_error not selected", exitcodes.ViolationReached, reachErrorMarker + "\n", []property.Property{property.NoOverflow}, NotConfirmed, ""},
		{"inconsistent", exitcodes.WitnessInconsistent, "", []property.Property{property.NoOverflow}, Inconsistent, ""},
		{"clean exit", 0, "", memsafety, NotConfirmed, ""},
		{"plain exit 1", 1, "runtime error: signed integer overflow", []property.Property{property.NoOverflow}, NotConfirmed, ""},

		{"add overflow", san, "<stdin>:4:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n", []property.Property{property.NoOverflow}, Confirmed, property.NoOverflow},
		{"division overflow", san, "u.c:4:28: runtime error: division of -2147483648 by -1 cannot be represented in type 'int'\n", []property.Property{property.NoOverflow}, Confirmed, property.NoOverflow},
		{"negation overflow", san, "u.c:4:95: runtime error: negation of -2147483648 cannot be represented in type 'int'; cast to an unsigned type to negate this value to itself\n", []property.Property{property.NoOverflow}, Confirmed, property.NoOverflow},
		{"shift overflow", san, "u.c:4:50: runtime error: left shift of 1 by 31 places cannot be represented in type 'int'\n", []property.Property{property.NoOverflow}, Confirmed, property.NoOverflow},
		{"shift of negative value", san, "u.c:4:188: runtime error: left shift of negative value -1\n", []property.Property{property.NoOverflow}, NotConfirmed, ""},
		{"shift exponent", san, "u.c:4:73: runtime error: shift exponent 40 is too large for 32-bit type 'int'\n", []property.Property{property.NoOverflow}, NotConfirmed, ""},
		{"overflow not selected", san, "u.c:4:9: runtime error: signed integer overflow: 1 + 1 cannot be represented in type 'int'\n", memsafety, NotConfirmed, ""},
		{"overflow message without sanitizer exit code", 3, "u.c:4:9: runtime error: signed integer overflow: 1 + 1 cannot be represented in type 'int'\n", []property.Property{property.NoOverflow}, NotConfirmed, ""},

		{"double free", san, "==1==ERROR: AddressSanitizer: attempting double-free on 0x7b in thread T0:\nSUMMARY: AddressSanitizer: double-free m.c:5 in main\n", memsafety, Confirmed, property.ValidFree},
		{"free of stack memory", san, "==1==ERROR: AddressSanitizer: alloc-dealloc-mismatch (INVALID vs free) on 0x7b\nSUMMARY: AddressSanitizer: alloc-dealloc-mismatch m.c:5 in main\n", memsafety, Confirmed, property.ValidFree},
		{"bad free", san, "==1==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x7 in thread T0\nSUMMARY: AddressSanitizer: bad-free m.c:5 in main\n", memsafety, Confirmed, property.ValidFree},
		{"use after free", san, "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x7b at pc 0x5\nSUMMARY: AddressSanitizer: heap-use-after-free m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"heap overflow", san, "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7c\nSUMMARY: AddressSanitizer: heap-buffer-overflow m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"stack overflow of buffer", san, "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7b\nSUMMARY: AddressSanitizer: stack-buffer-overflow m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"global overflow", san, "==1==ERROR: AddressSanitizer: global-buffer-overflow on address 0x56\nSUMMARY: AddressSanitizer: global-buffer-overflow m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"null dereference", san, "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55 bp 0x7f sp 0x7f T0)\nSUMMARY: AddressSanitizer: SEGV m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"use after return", san, "==1==ERROR: AddressSanitizer: stack-use-after-return on address 0x7b\nSUMMARY: AddressSanitizer: stack-use-after-return m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"use after scope", san, "==1==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7b\nSUMMARY: AddressSanitizer: stack-use-after-scope m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"stack underflow", san, "==1==ERROR: AddressSanitizer: stack-buffer-underflow on address 0x7b\nSUMMARY: AddressSanitizer: stack-buffer-underflow m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"variable-length array overflow", san, "==1==ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address 0x7b\nSUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow m.c:5 in main\n", memsafety, Confirmed, property.ValidDeref},
		{"leak", san, "==1==ERROR: LeakSanitizer: detected memory leaks\nSUMMARY: AddressSanitizer: 8 byte(s) leaked in 1 allocation(s).\n", memsafety, Confirmed, property.ValidMemtrack},
		{"stack exhaustion is no violation", san, "==1==ERROR: AddressSanitizer: stack-overflow on address 0x7f\nSUMMARY: AddressSanitizer: stack-overflow m.c:5 in f\n", memsafety, NotConfirmed, ""},
		{"overlapping memcpy is no violation", san, "==1==ERROR: AddressSanitizer: memcpy-param-overlap: memory ranges overlap\nSUMMARY: AddressSanitizer: memcpy-param-overlap m.c:5 in main\n", memsafety, NotConfirmed, ""},
		{"double free when only deref selected", san, "==1==ERROR: AddressSanitizer: attempting double-free on 0x7b in thread T0:\nSUMMARY: AddressSanitizer: double-free m.c:5 in main\n", []property.Property{property.ValidDeref}, NotConfirmed, ""},
		{"deref when only overflow selected", san, "==1==ERROR: AddressSanitizer: SEGV on unknown address\nSUMMARY: AddressSanitizer: SEGV m.c:5 in main\n", []property.Property{property.NoOverflow}, NotConfirmed, ""},

		{"memcleanup", exitcodes.MemcleanupViolation, memcleanupMarker + "\n", []property.Property{property.ValidMemcleanup}, Confirmed, property.ValidMemcleanup},
		{"memcleanup exit code without marker", exitcodes.MemcleanupViolation, "", []property.Property{property.ValidMemcleanup}, NotConfirmed, ""},
		{"memcleanup not selected", exitcodes.MemcleanupViolation, memcleanupMarker + "\n", memsafety, NotConfirmed, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.exitCode, tt.stderr, tt.properties)
			if got.status != tt.status || got.violated != tt.violated {
				t.Errorf("classify = %s %q, want %s %q", got.status, got.violated, tt.status, tt.violated)
			}
		})
	}
}

func TestClassifyExplainsUnclaimedViolation(t *testing.T) {
	got := classify(exitcodes.SanitizerReport,
		"==1==ERROR: AddressSanitizer: attempting double-free on 0x7b in thread T0:\nSUMMARY: AddressSanitizer: double-free m.c:5 in main\n",
		[]property.Property{property.ValidDeref})
	want := "execution violated valid-memsafety(valid-free), which is not among the checked properties"
	if got.detail != want {
		t.Errorf("detail = %q, want %q", got.detail, want)
	}
}
