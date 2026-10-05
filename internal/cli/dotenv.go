package cli

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/lminii/envs/internal/names"
)

type dotenvEntry struct {
	key   string
	value string
	line  int
}

// parseDotenv reads dotenv text. It never expands $VAR or ${VAR}, because a
// secret often contains "$". An error names the line and never quotes the
// text of the line, which can be a value.
func parseDotenv(data []byte) ([]dotenvEntry, error) {
	text := strings.TrimPrefix(string(data), string([]byte{0xEF, 0xBB, 0xBF}))
	if !utf8.ValidString(text) {
		return nil, errors.New("the file is not valid UTF-8")
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")

	var entries []dotenvEntry
	line := 1
	for i := 0; i < len(text); {
		i = skipBlanks(text, i)
		if i == len(text) {
			break
		}
		if text[i] == '\n' {
			i++
			line++
			continue
		}
		if text[i] == '#' {
			i = endOfLine(text, i)
			continue
		}

		end := endOfLine(text, i)
		eq := strings.IndexByte(text[i:end], '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: the line has no \"=\"", line)
		}
		key := strings.TrimSpace(text[i : i+eq])
		if rest, ok := strings.CutPrefix(key, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			key = strings.TrimSpace(rest)
		}
		if names.Key(key) != nil {
			return nil, fmt.Errorf("line %d: the key name is not valid. A key name uses letters, digits, and \"_\", and does not start with a digit", line)
		}
		entry := dotenvEntry{key: key, line: line}
		i = skipBlanks(text, i+eq+1)

		switch {
		case i < len(text) && (text[i] == '"' || text[i] == '\''):
			value, next, ok := quoted(text, i)
			if !ok {
				return nil, fmt.Errorf("line %d: the value has no closing quote", line)
			}
			entry.value = value
			line += strings.Count(text[i:next], "\n")
			i = skipBlanks(text, next)
			if i < len(text) && text[i] != '\n' && text[i] != '#' {
				return nil, fmt.Errorf("line %d: text follows the closing quote", line)
			}
			i = endOfLine(text, i)
		default:
			value := text[i:end]
			// A "#" starts a comment at the start of the value or after a blank.
			for j := 0; j < len(value); j++ {
				if value[j] == '#' && (j == 0 || value[j-1] == ' ' || value[j-1] == '\t') {
					value = value[:j]
					break
				}
			}
			entry.value = strings.TrimRight(value, " \t")
			i = end
		}
		if strings.ContainsRune(entry.value, 0) {
			return nil, fmt.Errorf("line %d: the value contains a NUL byte, and an environment variable cannot hold it", entry.line)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func skipBlanks(text string, i int) int {
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	return i
}

func endOfLine(text string, i int) int {
	if n := strings.IndexByte(text[i:], '\n'); n >= 0 {
		return i + n
	}
	return len(text)
}

// quoted reads the quoted value that starts at text[i] and returns the index
// after the closing quote. A value can span lines. Single quotes are
// literal. Double quotes accept the escapes \n, \r, \t, \", and \\.
func quoted(text string, i int) (value string, next int, ok bool) {
	quote := text[i]
	var b strings.Builder
	for j := i + 1; j < len(text); j++ {
		c := text[j]
		if c == quote {
			return b.String(), j + 1, true
		}
		if quote == '"' && c == '\\' && j+1 < len(text) {
			switch text[j+1] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '"', '\\':
				b.WriteByte(text[j+1])
			default:
				b.WriteByte(c)
				b.WriteByte(text[j+1])
			}
			j++
			continue
		}
		b.WriteByte(c)
	}
	return "", 0, false
}
