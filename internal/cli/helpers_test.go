package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/store"
)

const (
	passphrase = "correct horse battery staple"
	helperEnv  = "ENVS_CLI_HELPER"

	keychainService = "envs"
	keychainUser    = "store-key"
)

// TestMain makes the test binary a child program for "envs run" when
// helperEnv is set. Arguments: <output file> <variable name> <exit code>.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "1" {
		os.Exit(m.Run())
	}
	args := os.Args[1:]
	if err := os.WriteFile(args[0], []byte(os.Getenv(args[1])), 0o600); err != nil {
		os.Exit(99)
	}
	code, _ := strconv.Atoi(args[2])
	os.Exit(code)
}

// isolate points the home folder of the process at a temporary folder, so
// git reads no user configuration and no code path can reach the real ~/.envs.
func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	keyring.MockInit()
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func bareRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "remote.git")
	git(t, "", "init", "--quiet", "--bare", "--initial-branch=main", "--", dir)
	return dir
}

// rawClone is a clone that the test changes without envs, as a person with
// write access to the store does.
func rawClone(t *testing.T, remote string) *store.Store {
	t.Helper()
	s, _, err := store.Clone(t.Context(), remote, filepath.Join(t.TempDir(), "raw"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rawWrite(t *testing.T, s *store.Store, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(s.Root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func rawPush(t *testing.T, s *store.Store, message string, paths ...string) {
	t.Helper()
	if err := s.Commit(t.Context(), message, paths...); err != nil {
		t.Fatal(err)
	}
	if err := s.Push(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// rawCommit pushes one changed file to the remote.
func rawCommit(t *testing.T, remote, rel string, data []byte) {
	t.Helper()
	s := rawClone(t, remote)
	rawWrite(t, s, rel, data)
	rawPush(t, s, "outside envs", rel)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// projectDir returns a new folder with the given name. Its parent has a
// .git entry, so the link file search does not leave the test.
func projectDir(t *testing.T, name string) string {
	t.Helper()
	base := t.TempDir()
	for _, dir := range []string{filepath.Join(base, ".git"), filepath.Join(base, name)} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(base, name)
}

type result struct {
	stdout string
	stderr string
	code   int
}

// device is one machine: a home folder, a keychain, and a user at the prompts.
type device struct {
	t    *testing.T
	home string
	// keychain is the value of the keychain entry, or "" for none.
	keychain   string
	noKeychain bool
	terminal   bool
	// hidden and lines are the answers of the user, in sequence.
	hidden  []string
	lines   []string
	prompts []string
	// onHidden runs one time, at the next hidden prompt.
	onHidden func()
}

func newDevice(t *testing.T) *device {
	t.Helper()
	return &device{t: t, home: t.TempDir(), terminal: true}
}

// loadKeychain makes the keychain of this device the keychain of the process.
func (d *device) loadKeychain() {
	d.t.Helper()
	if d.noKeychain {
		keyring.MockInitWithError(errors.New("no keychain on this device"))
		return
	}
	keyring.MockInit()
	if d.keychain != "" {
		if err := keyring.Set(keychainService, keychainUser, d.keychain); err != nil {
			d.t.Fatal(err)
		}
	}
}

func (d *device) run(dir, stdin string, args ...string) result {
	d.t.Helper()
	d.loadKeychain()
	var stdout, stderr bytes.Buffer
	app := &App{
		Stdin:      strings.NewReader(stdin),
		Stdout:     &stdout,
		Stderr:     &stderr,
		Dir:        dir,
		Home:       d.home,
		IsTerminal: func() bool { return d.terminal },
		ReadHidden: func(prompt string) (string, error) {
			d.prompts = append(d.prompts, prompt)
			if hook := d.onHidden; hook != nil {
				d.onHidden = nil
				hook()
			}
			if len(d.hidden) == 0 {
				d.t.Errorf("unexpected hidden prompt %q", prompt)
				return "", errors.New("no answer")
			}
			answer := d.hidden[0]
			d.hidden = d.hidden[1:]
			return answer, nil
		},
		ReadLine: func(prompt string) (string, error) {
			d.prompts = append(d.prompts, prompt)
			if len(d.lines) == 0 {
				d.t.Errorf("unexpected prompt %q", prompt)
				return "", errors.New("no answer")
			}
			answer := d.lines[0]
			d.lines = d.lines[1:]
			return answer, nil
		},
	}
	code := app.Run(args)
	if !d.noKeychain {
		d.keychain, _ = keyring.Get(keychainService, keychainUser)
	}
	return result{stdout.String(), stderr.String(), code}
}

// ok runs a command that must succeed.
func (d *device) ok(dir, stdin string, args ...string) result {
	d.t.Helper()
	r := d.run(dir, stdin, args...)
	if r.code != 0 {
		d.t.Fatalf("envs %v: exit code %d\n%s", args, r.code, r.stderr)
	}
	return r
}

// fails runs a command that must fail with want in the error message.
func (d *device) fails(dir, stdin, want string, args ...string) result {
	d.t.Helper()
	r := d.run(dir, stdin, args...)
	if r.code == 0 {
		d.t.Fatalf("envs %v: exit code 0, want a failure", args)
	}
	if !strings.Contains(r.stderr, want) {
		d.t.Fatalf("envs %v: stderr = %q, want it to contain %q", args, r.stderr, want)
	}
	return r
}

// pipe runs a command with stdin that is not a terminal.
func (d *device) pipe(dir, stdin string, args ...string) result {
	d.t.Helper()
	d.terminal = false
	defer func() { d.terminal = true }()
	return d.ok(dir, stdin, args...)
}

func (d *device) pipeFails(dir, stdin, want string, args ...string) result {
	d.t.Helper()
	d.terminal = false
	defer func() { d.terminal = true }()
	return d.fails(dir, stdin, want, args...)
}

// login logs in. The first device of a store answers the passphrase two times.
func (d *device) login(remote string, first bool) {
	d.t.Helper()
	d.hidden = append(d.hidden, passphrase)
	if first {
		d.hidden = append(d.hidden, passphrase)
	}
	d.ok(d.home, "", "login", remote)
}

func (d *device) storeDir() string {
	return filepath.Join(d.home, ".envs", "store")
}

func (d *device) storeKey() string {
	d.t.Helper()
	key, _, ok := strings.Cut(d.keychain, ":")
	if !ok {
		d.t.Fatal("the keychain has no entry")
	}
	return key
}

// values decrypts a secret file in the local clone.
func (d *device) values(project, environment string) map[string]string {
	d.t.Helper()
	data := readFile(d.t, filepath.Join(d.storeDir(), project, environment+".age"))
	file, err := crypt.DecryptSecretFile(d.storeKey(), data, project, environment)
	if err != nil {
		d.t.Fatal(err)
	}
	return file.Values
}

// world is one remote, one logged-in device, and one linked project folder.
type world struct {
	remote string
	a      *device
	dir    string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	isolate(t)
	w := &world{remote: bareRepo(t), a: newDevice(t), dir: projectDir(t, "myapp")}
	w.a.login(w.remote, true)
	w.a.ok(w.dir, "", "init")
	return w
}

// second returns another logged-in device with its own linked project folder.
func (w *world) second(t *testing.T) (*device, string) {
	t.Helper()
	b := newDevice(t)
	b.login(w.remote, false)
	dir := projectDir(t, "myapp")
	// init asks only when the project exists in the store.
	b.lines = []string{"yes"}
	b.ok(dir, "", "init")
	b.lines, b.prompts = nil, nil
	return b, dir
}

// childValue runs "envs run" with a child that reports one variable.
func childValue(t *testing.T, d *device, dir, name string, flags ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv(helperEnv, "1")
	args := append([]string{"run"}, flags...)
	args = append(args, "--", exe, out, name, "0")
	d.ok(dir, "", args...)
	return string(readFile(t, out))
}

// assertNotOnDisk fails when a file below root contains one of the texts.
func assertNotOnDisk(t *testing.T, root string, texts ...string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, text := range texts {
			if bytes.Contains(data, []byte(text)) {
				t.Errorf("%s contains plaintext", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
