package runner

import "os"

var relayedSignals = []os.Signal{os.Interrupt}

// The console delivers Ctrl+C to the child too, so the parent only waits.
func relay(*os.Process, os.Signal) {}

func exitCode(state *os.ProcessState) int {
	return state.ExitCode()
}
