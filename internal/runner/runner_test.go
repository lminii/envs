package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const helperEnv = "ENVS_RUNNER_HELPER"

// TestMain makes the test binary a child program when helperEnv is set.
// Arguments: <output file> <variable name> <exit code> [sleep].
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "1" {
		os.Exit(m.Run())
	}
	args := os.Args[1:]
	if err := os.WriteFile(args[0], []byte(os.Getenv(args[1])), 0o600); err != nil {
		os.Exit(99)
	}
	if len(args) > 3 {
		time.Sleep(30 * time.Second)
	}
	code, _ := strconv.Atoi(args[2])
	os.Exit(code)
}

func helperArgv(t *testing.T, out, name string, code int, extra ...string) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(helperEnv, "1")
	return append([]string{exe, out, name, strconv.Itoa(code)}, extra...)
}

func TestRunInjectsValues(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		values map[string]string
		want   string
	}{
		{"new variable", "", map[string]string{"ENVS_TEST_VALUE": "stored"}, "stored"},
		{"stored value overrides the parent", "parent", map[string]string{"ENVS_TEST_VALUE": "stored"}, "stored"},
		{"parent variable stays", "parent", map[string]string{"OTHER": "x"}, "parent"},
		{"special characters", "", map[string]string{"ENVS_TEST_VALUE": "a b\"c'd\n$HOME %PATH% =&|"}, "a b\"c'd\n$HOME %PATH% =&|"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.parent != "" {
				t.Setenv("ENVS_TEST_VALUE", c.parent)
			}
			out := filepath.Join(t.TempDir(), "out")
			code, err := Run(helperArgv(t, out, "ENVS_TEST_VALUE", 0), c.values)
			if err != nil || code != 0 {
				t.Fatalf("Run = %d, %v", code, err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("child value = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRunReturnsExitCode(t *testing.T) {
	for _, want := range []int{0, 1, 3, 42} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			code, err := Run(helperArgv(t, out, "X", want), nil)
			if err != nil || code != want {
				t.Fatalf("Run = %d, %v, want %d", code, err, want)
			}
		})
	}
}

// writeProgram creates a program named prog in dir that exits with code 7.
// On Windows it is a batch file, which is the form of shims such as npx.
func writeProgram(t *testing.T, dir string) {
	t.Helper()
	name, content := "prog", "#!/bin/sh\nexit 7\n"
	if runtime.GOOS == "windows" {
		name, content = "prog.bat", "@exit /b 7\r\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestRunProgramInCurrentFolder(t *testing.T) {
	dir := t.TempDir()
	writeProgram(t, dir)
	t.Chdir(dir)

	// When this Windows variable is set, the search skips the current folder.
	const noCurrentDir = "NoDefaultCurrentDirectoryInExePath"
	if old, set := os.LookupEnv(noCurrentDir); set {
		os.Unsetenv(noCurrentDir)
		t.Cleanup(func() { os.Setenv(noCurrentDir, old) })
	}

	t.Run("bare name is refused", func(t *testing.T) {
		_, err := Run([]string{"prog"}, nil)
		if err == nil || !strings.Contains(err.Error(), "does not start a program from the current folder") {
			t.Fatalf("error = %v, want the current folder error", err)
		}
	})
	t.Run("bare name is refused when the search skips the current folder", func(t *testing.T) {
		t.Setenv(noCurrentDir, "1")
		_, err := Run([]string{"prog"}, nil)
		if runtime.GOOS == "windows" {
			if err == nil || !strings.Contains(err.Error(), "is not on the PATH") {
				t.Fatalf("error = %v, want a not found error", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "does not start a program from the current folder") {
			t.Fatalf("error = %v, want the current folder error", err)
		}
	})
	t.Run("explicit path starts", func(t *testing.T) {
		code, err := Run([]string{"./prog"}, nil)
		if err != nil || code != 7 {
			t.Fatalf("Run = %d, %v, want 7", code, err)
		}
	})
}

func TestRunProgramOnPath(t *testing.T) {
	dir := t.TempDir()
	writeProgram(t, dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	code, err := Run([]string{"prog"}, nil)
	if err != nil || code != 7 {
		t.Fatalf("Run = %d, %v, want 7", code, err)
	}
}

func TestRunProgramNotFound(t *testing.T) {
	_, err := Run([]string{"envs-program-that-does-not-exist"}, map[string]string{"K": "s3cret"})
	if err == nil || !strings.Contains(err.Error(), "is not on the PATH") {
		t.Fatalf("error = %v, want a not found error", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error contains a value: %v", err)
	}
}
