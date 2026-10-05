// Package runner starts the child process of "envs run" (PRD 8.9).
package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
)

// Run starts argv with the parent environment plus values, waits for it, and
// returns its exit code. It never starts the program through a shell.
func Run(argv []string, values map[string]string) (int, error) {
	path, err := exec.LookPath(argv[0])
	if errors.Is(err, exec.ErrDot) {
		return 0, fmt.Errorf("the program %q is in the current folder, and envs does not start a program from the current folder. Use an explicit path such as ./%s", argv[0], argv[0])
	}
	if err != nil {
		return 0, fmt.Errorf("the program %q is not on the PATH. Check the command after \"envs run --\"", argv[0])
	}

	// cmd.exe reads "./prog.bat" as the command "." with a switch, and
	// exec.Command searches again for a name without a folder.
	path, err = filepath.Abs(path)
	if err != nil {
		return 0, fmt.Errorf("cannot resolve the program %q: %v", argv[0], err)
	}

	cmd := exec.Command(path, argv[1:]...)
	// A later entry wins, so a stored value overrides a parent variable.
	cmd.Env = os.Environ()
	for key, value := range values {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	signals := make(chan os.Signal, 8)
	signal.Notify(signals, relayedSignals...)
	defer signal.Stop(signals)

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("cannot start the program %q: %v", argv[0], err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-signals:
				relay(cmd.Process, s)
			case <-done:
				return
			}
		}
	}()

	err = cmd.Wait()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return 0, fmt.Errorf("cannot wait for the program %q: %v", argv[0], err)
	}
	return exitCode(cmd.ProcessState), nil
}
