// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"testing"
)

func TestMaskedSource(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain code", "int x = a / b;", "int x = a / b;"},
		{"line comment", "x = 1; // if (y) ?\ny = 2;", "x = 1;            \ny = 2;"},
		{"block comment", "x = /* if ( */ 1;", "x =            1;"},
		{"block comment over lines", "a; /* b\n c \n d */ e;", "a;     \n   \n      e;"},
		{"unterminated block comment", "a; /* b\nc", "a;     \n "},
		{"line comment inside block comment", "/* // */ x;", "         x;"},
		{"block comment start inside line comment", "// /*\nx; /* y */", "     \nx;        "},
		{"string literal", `s = "if (a) ? b : c";`, `s =                 ;`},
		{"string with escaped quote", `s = "a\"b"; t;`, `s =       ; t;`},
		{"string ending in escaped backslash", `s = "a\\"; t;`, `s =      ; t;`},
		{"string with comment start", `s = "/*"; t; u = "//"; v;`, `s =     ; t; u =     ; v;`},
		{"char literal", `c = '?'; d = '(';`, `c =    ; d =    ;`},
		{"char literal with quote", `c = '"'; d = "'"; e;`, `c =    ; d =    ; e;`},
		{"escaped char literal", `c = '\''; d = '\\'; e;`, `c =     ; d =     ; e;`},
		{"unterminated string ends at the newline", "s = \"abc\nx = 1;", "s =     \nx = 1;"},
		{"unterminated char ends at the newline", "#error don't\nx = 1;", "#error don  \nx = 1;"},
		{"continued line comment", "// a \\\nb\nc;", "      \n \nc;"},
		{"continued line comment with carriage return", "// a \\\r\nb\nc;", "       \n \nc;"},
		{"continued string", "s = \"a\\\nb\"; c;", "s =    \n  ; c;"},
		{"comment directly after code", "a/**/b//c", "a    b   "},
		{"division is not a comment", "a = b / c / d;", "a = b / c / d;"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newSourceText(tt.in).masked
			if got != tt.want {
				t.Errorf("masked source of %q:\ngot  %q\nwant %q", tt.in, got, tt.want)
			}
			if len(got) != len(tt.in) {
				t.Errorf("length changed from %d to %d", len(tt.in), len(got))
			}
		})
	}
}

func TestSourceTextLines(t *testing.T) {
	src := newSourceText("ab\n\n  c /* x */\nlast")
	if src.lineCount() != 4 {
		t.Fatalf("lineCount = %d, want 4", src.lineCount())
	}
	wantLines := []string{"ab", "", "  c /* x */", "last"}
	wantMasked := []string{"ab", "", "  c        ", "last"}
	wantStarts := []int{0, 3, 4, 16}
	for i := range wantLines {
		n := i + 1
		if got := src.line(n); got != wantLines[i] {
			t.Errorf("line(%d) = %q, want %q", n, got, wantLines[i])
		}
		if got := src.maskedLine(n); got != wantMasked[i] {
			t.Errorf("maskedLine(%d) = %q, want %q", n, got, wantMasked[i])
		}
		if got := src.lineStart(n); got != wantStarts[i] {
			t.Errorf("lineStart(%d) = %d, want %d", n, got, wantStarts[i])
		}
	}
	positions := []struct{ offset, line, column int }{
		{0, 1, 1}, {1, 1, 2}, {2, 1, 3}, {3, 2, 1}, {4, 3, 1}, {6, 3, 3}, {16, 4, 1}, {19, 4, 4},
	}
	for _, p := range positions {
		if line, column := src.position(p.offset); line != p.line || column != p.column {
			t.Errorf("position(%d) = %d:%d, want %d:%d", p.offset, line, column, p.line, p.column)
		}
	}
}

func TestSourceTextTrailingNewline(t *testing.T) {
	// The (empty) text after the last newline counts as a line, like for
	// strings.Split. No waypoint can match anything there.
	src := newSourceText("a;\n")
	if src.lineCount() != 2 || src.line(1) != "a;" || src.line(2) != "" {
		t.Errorf("lineCount = %d, lines %q and %q", src.lineCount(), src.line(1), src.line(2))
	}
}

func TestMatchingParenthesis(t *testing.T) {
	tests := []struct {
		text  string
		open  int
		close int
	}{
		{"(a)", 0, 2},
		{"if (a && (b || c)) x;", 3, 17},
		{"if (a && (b || c)) x;", 9, 16},
		{"f() + (g())", 6, 10},
		{"(a", 0, -1},
		{"(a\n)", 0, -1},
		{"((a)", 0, -1},
	}
	for _, tt := range tests {
		if got := matchingClose(tt.text, tt.open); got != tt.close {
			t.Errorf("matchingClose(%q, %d) = %d, want %d", tt.text, tt.open, got, tt.close)
		}
		if tt.close >= 0 {
			if got := matchingOpen(tt.text, tt.close); got != tt.open {
				t.Errorf("matchingOpen(%q, %d) = %d, want %d", tt.text, tt.close, got, tt.open)
			}
		}
	}
	for _, tt := range []struct {
		text  string
		close int
	}{
		{"a)", 1},
		{"(\na)", 3},
		{"(a))", 3},
	} {
		if got := matchingOpen(tt.text, tt.close); got != -1 {
			t.Errorf("matchingOpen(%q, %d) = %d, want -1", tt.text, tt.close, got)
		}
	}
}

func TestMatchingBrace(t *testing.T) {
	tests := []struct {
		text  string
		open  int
		close int
	}{
		{"{}", 0, 1},
		{"do {\n  if (x) { y; }\n} while (z);", 3, 21},
		{"{ { }", 0, -1},
	}
	for _, tt := range tests {
		if got := matchingBrace(tt.text, tt.open); got != tt.close {
			t.Errorf("matchingBrace(%q, %d) = %d, want %d", tt.text, tt.open, got, tt.close)
		}
	}
}

func TestIsWordAt(t *testing.T) {
	tests := []struct {
		text string
		pos  int
		word string
		want bool
	}{
		{"if (x)", 0, "if", true},
		{"  if(x)", 2, "if", true},
		{"else if (x)", 5, "if", true},
		{"}while(x)", 1, "while", true},
		{"do", 0, "do", true},
		{"double d;", 0, "do", false},
		{"redo {", 2, "do", false},
		{"_if (x)", 1, "if", false},
		{"x9if (x)", 2, "if", false},
		{"iffy", 0, "if", false},
		{"if", 1, "if", false},
		{"if", 5, "if", false},
		{"if", -1, "if", false},
	}
	for _, tt := range tests {
		if got := isWordAt(tt.text, tt.pos, tt.word); got != tt.want {
			t.Errorf("isWordAt(%q, %d, %q) = %v, want %v", tt.text, tt.pos, tt.word, got, tt.want)
		}
	}
}
