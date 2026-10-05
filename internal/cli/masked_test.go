package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadMasked(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		want     string
		wantEcho string
	}{
		{"enter on Windows", "s3cret\r", "s3cret", "******"},
		{"enter on Unix", "s3cret\n", "s3cret", "******"},
		{"only the first line", "one\rtwo\r", "one", "***"},
		{"end of input", "s3cret", "s3cret", "******"},
		{"empty", "\r", "", ""},
		{"blanks stay", " a b \r", " a b ", "*****"},
		{"backspace", "abc\x7f\x7fd\r", "ad", "***\b \b\b \b*"},
		{"backspace on Windows", "abc\bd\r", "abd", "***\b \b*"},
		{"backspace on an empty line", "\x7f\x7fa\r", "a", "*"},
		{"one star for one character", "pä한\r", "pä한", "***"},
		{"backspace removes one character", "pä한\x7f\x7f\r", "p", "***\b \b\b \b"},
		{"Ctrl+U clears the line", "abc\x15de\r", "de", "***\b \b\b \b\b \b**"},
		{"other control characters are ignored", "a\x1b\tb\r", "ab", "**"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var echo bytes.Buffer
			got, err := readMasked(strings.NewReader(c.in), &echo)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("value = %q, want %q", got, c.want)
			}
			if echo.String() != c.wantEcho {
				t.Errorf("echo = %q, want %q", echo.String(), c.wantEcho)
			}
		})
	}
}

func TestReadMaskedStops(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"Ctrl+C", "s3c\x03ret\r", errInterrupted},
		{"Ctrl+D on an empty line", "\x04", io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var echo bytes.Buffer
			got, err := readMasked(strings.NewReader(c.in), &echo)
			if !errors.Is(err, c.want) || got != "" {
				t.Fatalf("readMasked = %q, %v, want %v", got, err, c.want)
			}
			if strings.Contains(echo.String(), "s3c") {
				t.Errorf("echo contains the input: %q", echo.String())
			}
		})
	}
}
