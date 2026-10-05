package cli

import (
	"errors"
	"io"
)

var errInterrupted = errors.New("stopped by Ctrl+C")

// readMasked reads one line from a terminal in raw mode and writes one "*"
// to echo for each character. It never writes the input itself.
func readMasked(r io.Reader, echo io.Writer) (string, error) {
	var line []byte
	erase := func() {
		for len(line) > 0 {
			last := line[len(line)-1]
			line = line[:len(line)-1]
			// A UTF-8 character ends at its first byte.
			if last&0xC0 != 0x80 {
				io.WriteString(echo, "\b \b")
				return
			}
		}
	}
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			switch c := buf[0]; {
			case c == '\r' || c == '\n':
				return string(line), nil
			case c == 0x03:
				return "", errInterrupted
			case c == 0x04 && len(line) == 0:
				return "", io.ErrUnexpectedEOF
			case c == 0x7f || c == '\b':
				erase()
			case c == 0x15:
				for len(line) > 0 {
					erase()
				}
			case c < 0x20:
			default:
				line = append(line, c)
				if c&0xC0 != 0x80 {
					io.WriteString(echo, "*")
				}
			}
		}
		if err == io.EOF {
			return string(line), nil
		}
		if err != nil {
			return "", err
		}
	}
}
