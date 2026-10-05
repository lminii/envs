package cli

import (
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []dotenvEntry
	}{
		{"plain", "A=1\nB=two\n", []dotenvEntry{{"A", "1", 1}, {"B", "two", 2}}},
		{"no final line ending", "A=1", []dotenvEntry{{"A", "1", 1}}},
		{"CRLF", "A=1\r\nB=2\r\n", []dotenvEntry{{"A", "1", 1}, {"B", "2", 2}}},
		{"BOM", "\xef\xbb\xbfA=1\n", []dotenvEntry{{"A", "1", 1}}},
		{"comments and blank lines", "# top\n\n  # indented\nA=1\n", []dotenvEntry{{"A", "1", 4}}},
		{"export", "export A=1\nexport\tB=2\n", []dotenvEntry{{"A", "1", 1}, {"B", "2", 2}}},
		{"key named export", "export=1\n", []dotenvEntry{{"export", "1", 1}}},
		{"blanks around the key and value", "  A  =  1  \n", []dotenvEntry{{"A", "1", 1}}},
		{"empty value", "A=\nB=\"\"\nC=''\n", []dotenvEntry{{"A", "", 1}, {"B", "", 2}, {"C", "", 3}}},
		{"no expansion", "A=$HOME\nB=\"${HOME}\"\nC='$(id)'\nD=pa$$word\n", []dotenvEntry{{"A", "$HOME", 1}, {"B", "${HOME}", 2}, {"C", "$(id)", 3}, {"D", "pa$$word", 4}}},
		{"value with equals signs", "A=abc==\n", []dotenvEntry{{"A", "abc==", 1}}},
		{"inline comment", "A=1 # note\nB=1#2\nC= # only a comment\n", []dotenvEntry{{"A", "1", 1}, {"B", "1#2", 2}, {"C", "", 3}}},
		{"quotes keep blanks and hash", "A=\" x # y \"\nB=' x # y '\n", []dotenvEntry{{"A", " x # y ", 1}, {"B", " x # y ", 2}}},
		{"comment after a quote", "A=\"1\" # note\nB=2\n", []dotenvEntry{{"A", "1", 1}, {"B", "2", 2}}},
		{"double quote escapes", `A="a\nb\tc\"d\\e\$f"` + "\n", []dotenvEntry{{"A", "a\nb\tc\"d\\e\\$f", 1}}},
		{"single quotes are literal", `A='a\nb"c'` + "\n", []dotenvEntry{{"A", `a\nb"c`, 1}}},
		{"quoted value on more than one line", "A=\"line1\nline2\"\nB=2\n", []dotenvEntry{{"A", "line1\nline2", 1}, {"B", "2", 3}}},
		{"quote inside an unquoted value", "A=it's\n", []dotenvEntry{{"A", "it's", 1}}},
		{"same key two times", "A=1\nA=2\n", []dotenvEntry{{"A", "1", 1}, {"A", "2", 2}}},
		{"empty file", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDotenv([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %d entries, want %d: %+v", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("entry %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestParseDotenvErrors(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantMsg string
	}{
		{"invalid key", "A=1\nMY-KEY=s3cret\n", "line 2: the key name is not valid"},
		{"key starts with a digit", "1A=s3cret\n", "line 1: the key name is not valid"},
		{"empty key", "=s3cret\n", "line 1: the key name is not valid"},
		{"no equals sign", "A=1\n\ns3cret\n", "line 3: the line has no \"=\""},
		{"no closing quote", "A=1\nB=\"s3cret\nC=2\n", "line 2: the value has no closing quote"},
		{"text after the closing quote", "A=\"s3cret\"x\n", "line 1: text follows the closing quote"},
		{"line number after a value on two lines", "A=\"x\ny\"\nMY-KEY=s3cret\n", "line 3: the key name is not valid"},
		{"NUL byte", "A=s3cret\x00\n", "line 1: the value contains a NUL byte"},
		{"not UTF-8", "A=s3cret\xff\n", "not valid UTF-8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseDotenv([]byte(c.in))
			if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("error = %v, want it to contain %q", err, c.wantMsg)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error contains a value: %v", err)
			}
		})
	}
}
