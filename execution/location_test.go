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

	"witness2test/property"
)

func TestViolationLine(t *testing.T) {
	tests := []struct {
		name     string
		violated property.Property
		stderr   string
		line     int
		found    bool
	}{
		{"reach_error", property.UnreachCall, "some output\nwitness2test-match: reach_error called at line 23\n", 23, true},
		{"reach_error without marker", property.UnreachCall, "", 0, false},
		{"overflow", property.NoOverflow, "<stdin>:7:13: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n", 7, true},
		{"overflow after unrelated report", property.NoOverflow, "<stdin>:3:5: runtime error: left shift of negative value -1\n<stdin>:9:2: runtime error: negation of -2147483648 cannot be represented in type 'int'\n", 9, true},
		{"program frame of invalid access", property.ValidDeref, "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7c at pc 0x55\nREAD of size 4 at 0x7c thread T0\n    #0 0x55aa in main <stdin>:12\n    #1 0x7f in __libc_start_call_main\n\n0x7c is located 0 bytes after 8-byte region\nallocated by thread T0 here:\n    #0 0x7f in malloc\n    #1 0x55 in main <stdin>:10\n", 12, true},
		{"library frame first", property.ValidFree, "==1==ERROR: AddressSanitizer: attempting double-free on 0x7b in thread T0:\n    #0 0x7f11 in free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:51\n    #1 0x55bb in release <stdin>:31\n    #2 0x55cc in main <stdin>:40\n", 31, true},
		{"frame with column", property.ValidDeref, "    #0 0x55aa in main <stdin>:12:7\n", 12, true},
		{"frame with directory", property.ValidDeref, "    #0 0x55aa in main /some dir/x/<stdin>:12\n", 12, true},
		{"no program frame", property.ValidDeref, "==1==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x7f in strlen\n", 0, false},
		{"memtrack is not located", property.ValidMemtrack, "    #1 0x55 in main <stdin>:10\n", 0, false},
		{"memcleanup is not located", property.ValidMemcleanup, memcleanupMarker + "\n", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, found := ViolationLine(tt.violated, tt.stderr)
			if line != tt.line || found != tt.found {
				t.Errorf("ViolationLine = %d, %v; want %d, %v", line, found, tt.line, tt.found)
			}
		})
	}
}

// The reported lines must be lines of the program as fed to the compiler.
func TestViolationLineOnRealReports(t *testing.T) {
	overflow := "#include <limits.h>\nvolatile int max = INT_MAX;\nint main(void){\n  int r = 0;\n  r = max + 1;\n  return r == 0;\n}\n"
	deref := "#include <stdlib.h>\nvolatile int two = 2;\nint main(void){\n  int *p = malloc(8);\n  int r =\n    p[two];\n  free(p);\n  return r;\n}\n"
	doubleFree := "#include <stdlib.h>\nvoid release(int *p){\n  free(p);\n}\nint main(void){\n  int *p = malloc(8);\n  release(p);\n  release(p);\n  return 0;\n}\n"
	for _, model := range []string{"LP64", "ILP32"} {
		for _, tt := range []struct {
			name     string
			program  string
			property property.Property
			line     int
		}{
			{"overflow", overflow, property.NoOverflow, 5},
			// The sanitizer reports the line on which the statement starts.
			{"deref", deref, property.ValidDeref, 5},
			{"double free", doubleFree, property.ValidFree, 3},
		} {
			t.Run(model+"/"+tt.name, func(t *testing.T) {
				v := runWithProperties(t, model, tt.program, []property.Property{tt.property})
				line, found := ViolationLine(v.Violated, v.Stderr)
				if !found || line != tt.line {
					t.Errorf("ViolationLine = %d, %v; want %d, true\nstderr: %s", line, found, tt.line, v.Stderr)
				}
			})
		}
	}
}
