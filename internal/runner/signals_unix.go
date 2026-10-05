//go:build unix

package runner

import (
	"os"
	"syscall"
)

var relayedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}

func relay(child *os.Process, s os.Signal) {
	_ = child.Signal(s)
}

func exitCode(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}
