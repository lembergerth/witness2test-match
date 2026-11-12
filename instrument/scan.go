// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"sort"
	"strings"
)

// charKind tells whether a byte of the program is code or part of a comment
// or literal.
type charKind uint8

const (
	kindCode charKind = iota
	kindLineComment
	kindBlockComment
	kindString
	kindCharLiteral
)

// sourceText is a program together with what text scanning needs to not be
// confused by comments and literals. Lines and columns are 1-based, offsets
// are 0-based byte offsets into text.
type sourceText struct {
	text string
	// masked is text with every byte of a comment, string literal or
	// character literal replaced by a space. Newlines are kept, so offsets,
	// lines and columns are the same as in text.
	masked string
	// kinds holds the kind of every byte of text.
	kinds []charKind
	// starts holds the offset of the first byte of every line.
	starts []int
}

func newSourceText(text string) *sourceText {
	kinds := classify(text)
	masked := []byte(text)
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		} else if kinds[i] != kindCode {
			masked[i] = ' '
		}
	}
	return &sourceText{text: text, masked: string(masked), kinds: kinds, starts: starts}
}

// classify determines the kind of every byte of text. A newline that ends a
// line comment or an unterminated literal is code. Inside a block comment,
// and where a backslash continues a line comment or a literal on the next
// line, the newline has the kind of the comment or literal.
func classify(text string) []charKind {
	kinds := make([]charKind, len(text))
	n := len(text)
	i := 0
	for i < n {
		switch c := text[i]; {
		case c == '/' && i+1 < n && text[i+1] == '/':
			for i < n && (text[i] != '\n' || isContinuedNewline(text, i)) {
				kinds[i] = kindLineComment
				i++
			}
		case c == '/' && i+1 < n && text[i+1] == '*':
			end := n
			if closing := strings.Index(text[i+2:], "*/"); closing >= 0 {
				end = i + 2 + closing + 2
			}
			for ; i < end; i++ {
				kinds[i] = kindBlockComment
			}
		case c == '"' || c == '\'':
			kind := kindString
			if c == '\'' {
				kind = kindCharLiteral
			}
			kinds[i] = kind
			i++
			for i < n && (text[i] != '\n' || isContinuedNewline(text, i)) {
				kinds[i] = kind
				if text[i] == '\\' && i+1 < n && text[i+1] != '\n' && text[i+1] != '\r' {
					// Escape sequence: the next byte cannot end the literal.
					kinds[i+1] = kind
					i += 2
					continue
				}
				i++
				if text[i-1] == c {
					break
				}
			}
		default:
			i++
		}
	}
	return kinds
}

// isContinuedNewline reports whether the newline at offset i is preceded by a
// backslash, which makes the next line a continuation of the current one.
func isContinuedNewline(text string, i int) bool {
	if i > 0 && text[i-1] == '\r' {
		i--
	}
	return i > 0 && text[i-1] == '\\'
}

func (s *sourceText) lineCount() int {
	return len(s.starts)
}

// lineStart returns the offset of the first byte of the given 1-based line.
func (s *sourceText) lineStart(line int) int {
	return s.starts[line-1]
}

// lineEnd returns the offset of the newline that ends the given 1-based line,
// or the length of the text for the last line.
func (s *sourceText) lineEnd(line int) int {
	if line < len(s.starts) {
		return s.starts[line] - 1
	}
	return len(s.text)
}

// line returns the given 1-based line without its newline.
func (s *sourceText) line(line int) string {
	return s.text[s.lineStart(line):s.lineEnd(line)]
}

// maskedLine is like line, for the masked text.
func (s *sourceText) maskedLine(line int) string {
	return s.masked[s.lineStart(line):s.lineEnd(line)]
}

// position converts an offset into a 1-based line and column.
func (s *sourceText) position(offset int) (line, column int) {
	line = sort.Search(len(s.starts), func(i int) bool { return s.starts[i] > offset })
	return line, offset - s.starts[line-1] + 1
}

// isCode reports whether all bytes in [from, to) are code.
func (s *sourceText) isCode(from, to int) bool {
	for i := from; i < to; i++ {
		if s.kinds[i] != kindCode {
			return false
		}
	}
	return true
}

// matchingClose returns the offset of the ')' that closes the '(' at offset
// open. Both must be on the same line; otherwise the result is -1. The text
// must be masked.
func matchingClose(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '\n':
			return -1
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// matchingOpen returns the offset of the '(' that is closed by the ')' at
// offset close. Both must be on the same line; otherwise the result is -1.
// The text must be masked.
func matchingOpen(text string, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		switch text[i] {
		case '\n':
			return -1
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// matchingBrace returns the offset of the '}' that closes the '{' at offset
// open, which may be on a later line, or -1. The text must be masked.
func matchingBrace(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isLineSpace reports whether c is whitespace other than a newline.
func isLineSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v'
}

// isWordAt reports whether word is at offset pos of text as a whole word,
// i.e., not as part of a longer identifier.
func isWordAt(text string, pos int, word string) bool {
	if pos < 0 || pos > len(text) || !strings.HasPrefix(text[pos:], word) {
		return false
	}
	if pos > 0 && isIdentChar(text[pos-1]) {
		return false
	}
	end := pos + len(word)
	return end == len(text) || !isIdentChar(text[end])
}

// skipLineSpace returns the first offset at or after pos that is not
// whitespace within the line.
func skipLineSpace(text string, pos int) int {
	for pos < len(text) && isLineSpace(text[pos]) {
		pos++
	}
	return pos
}

// skipSpace is like skipLineSpace and also skips newlines.
func skipSpace(text string, pos int) int {
	for pos < len(text) && (isLineSpace(text[pos]) || text[pos] == '\n') {
		pos++
	}
	return pos
}

// skipLineSpaceBackward returns the last offset at or before pos that is not
// whitespace within the line, or -1 if there is none before the start of the
// text. The result can be the offset of a newline.
func skipLineSpaceBackward(text string, pos int) int {
	for pos >= 0 && isLineSpace(text[pos]) {
		pos--
	}
	return pos
}
