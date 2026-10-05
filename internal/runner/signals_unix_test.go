//go:build unix

package runner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRunForwardsSignals(t *testing.T) {
	cases := []struct {
		name   string
		signal syscall.Signal
	}{
		{"SIGINT", syscall.SIGINT},
		{"SIGTERM", syscall.SIGTERM},
		{"SIGHUP", syscall.SIGHUP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			argv := helperArgv(t, out, "X", 0, "sleep")
			go func() {
				// The child writes the file before it sleeps.
				for {
					if _, err := os.Stat(out); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				_ = syscall.Kill(os.Getpid(), c.signal)
			}()
			code, err := Run(argv, nil)
			if err != nil {
				t.Fatal(err)
			}
			if want := 128 + int(c.signal); code != want {
				t.Fatalf("exit code = %d, want %d", code, want)
			}
		})
	}
}
