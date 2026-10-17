package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/link"
	"github.com/lminii/envs/internal/store"
)

// Each test in this file covers one row of the threat table in README.md.

const outsideEnvs = "The store was changed outside envs"

// childDidNotStart runs "envs run", which must fail with want, and checks
// that the child program did not start.
func childDidNotStart(t *testing.T, d *device, dir, want string, flags ...string) result {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv(helperEnv, "1")
	args := append([]string{"run"}, flags...)
	args = append(args, "--", exe, out, "API_KEY", "0")
	r := d.fails(dir, "", want, args...)
	if _, err := os.Stat(out); err == nil {
		t.Error("the child program started")
	}
	return r
}

func remoteFile(t *testing.T, w *world, rel string) []byte {
	t.Helper()
	return readFile(t, filepath.Join(rawClone(t, w.remote).Root, rel))
}

// Threat: a person reads the store repository.
func TestThreat_StoreRead(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "s3cret-value-0001", "set", "API_KEY")

	raw := rawClone(t, w.remote)
	t.Run("all values are encrypted", func(t *testing.T) {
		assertNotOnDisk(t, raw.Root, "s3cret-value-0001", w.a.storeKey())
		for _, rel := range []string{"key.age", "myapp/dev.age"} {
			if data := readFile(t, filepath.Join(raw.Root, rel)); !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n-> scrypt ")) {
				t.Errorf("%s is not an age passphrase file", rel)
			}
		}
		// The content of a secret file is not readable without the store key.
		if bytes.Contains(readFile(t, filepath.Join(raw.Root, "myapp", "dev.age")), []byte("API_KEY")) {
			t.Error("a secret file shows a key name")
		}
	})
	t.Run("the store key needs the passphrase", func(t *testing.T) {
		keyFile := readFile(t, filepath.Join(raw.Root, "key.age"))
		if !bytes.Contains(keyFile, []byte(" 18\n")) {
			t.Error("key.age does not use scrypt work factor 18")
		}
		if _, err := crypt.DecryptKeyFile("a guess of sixteen+ characters", keyFile); !errors.Is(err, crypt.ErrWrongKey) {
			t.Errorf("error = %v, want ErrWrongKey", err)
		}
		b := newDevice(t)
		b.hidden = []string{"a guess of sixteen+ characters"}
		b.fails(b.home, "", "the passphrase is wrong. Run \"envs login\" again", "login", w.remote)
	})
	t.Run("a passphrase has 16 characters or more", func(t *testing.T) {
		d := newDevice(t)
		d.hidden = []string{"only15character"}
		d.fails(d.home, "", "the passphrase has fewer than 16 characters. Run \"envs login\" again with a longer passphrase", "login", bareRepo(t))
	})
}

// Threat: a person with write access adds a file with values of their choice.
func TestThreat_ForgedFile(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "real-value", "set", "API_KEY")

	attackerKey, err := crypt.NewStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	forged := crypt.NewSecretFile("myapp", "dev")
	forged.Values["API_KEY"] = "attacker-value"
	encrypted, err := crypt.EncryptSecretFile(attackerKey, forged)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"encrypted with another key", encrypted, "the store key cannot decrypt myapp/dev.age. " + outsideEnvs},
		{"plaintext JSON", []byte(`{"version":1,"project":"myapp","environment":"dev","values":{"API_KEY":"attacker-value"}}`), "cannot use myapp/dev.age"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rawCommit(t, w.remote, "myapp/dev.age", c.data)
			r := childDidNotStart(t, w.a, w.dir, c.want)
			if !strings.Contains(r.stderr, outsideEnvs) {
				t.Errorf("stderr = %q, want %q", r.stderr, outsideEnvs)
			}
			w.a.fails(w.dir, "", c.want, "list")
			w.a.pipeFails(w.dir, "new-value", c.want, "set", "OTHER")
			if !bytes.Equal(remoteFile(t, w, "myapp/dev.age"), c.data) {
				t.Error("envs wrote to the forged file")
			}
		})
	}
	t.Run("a forged file for a new environment", func(t *testing.T) {
		forged := crypt.NewSecretFile("myapp", "staging")
		forged.Values["API_KEY"] = "attacker-value"
		data, err := crypt.EncryptSecretFile(attackerKey, forged)
		if err != nil {
			t.Fatal(err)
		}
		rawCommit(t, w.remote, "myapp/staging.age", data)
		childDidNotStart(t, w.a, w.dir, "the store key cannot decrypt myapp/staging.age. "+outsideEnvs, "--env", "staging")
	})
}

// Threat: a person with write access copies a file to a different project.
func TestThreat_MovedFile(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "myapp-dev", "set", "API_KEY")
	w.a.pipe(w.dir, "myapp-prod", "set", "API_KEY", "--env", "prod")
	w.a.pipe(w.dir, "other-dev", "set", "API_KEY", "--project", "other")

	cases := []struct {
		name string
		from string
		want string
	}{
		{"from another project", "other/dev.age", "cannot use myapp/dev.age: damaged file: the content belongs to other/dev. The file was moved. " + outsideEnvs},
		{"from another environment", "myapp/prod.age", "cannot use myapp/dev.age: damaged file: the content belongs to myapp/prod. The file was moved. " + outsideEnvs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rawCommit(t, w.remote, "myapp/dev.age", remoteFile(t, w, c.from))
			childDidNotStart(t, w.a, w.dir, c.want)
			w.a.fails(w.dir, "", c.want, "list")
			w.a.pipeFails(w.dir, "new-value", c.want, "set", "OTHER")
		})
	}
}

// Threat: a person with write access deletes key.age to make a new device create a new key.
func TestThreat_DeletedKeyFile(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")

	raw := rawClone(t, w.remote)
	if err := os.Remove(raw.KeyPath()); err != nil {
		t.Fatal(err)
	}
	rawPush(t, raw, "outside envs", store.KeyFileName)
	head := git(t, w.remote, "rev-parse", "main")

	b := newDevice(t)
	// No answer is queued, so a passphrase prompt fails the test.
	r := b.fails(b.home, "", "the repository has commits and no key.age. envs creates a store key only in an empty repository", "login", w.remote)
	if !strings.Contains(r.stderr, "restore key.age from the git history") {
		t.Errorf("stderr = %q, want the corrective step", r.stderr)
	}
	if len(b.prompts) != 0 {
		t.Errorf("the login asked for a new passphrase: %q", b.prompts)
	}
	if b.keychain != "" {
		t.Error("the login created a key")
	}
	if _, err := os.Stat(b.storeDir()); err == nil {
		t.Error("the failed login left a clone")
	}
	if git(t, w.remote, "rev-parse", "main") != head {
		t.Error("the login pushed a commit")
	}
}

// Threat: a person with write access raises the scrypt work factor in a file
// header, or adds a very large file.
func TestThreat_WorkFactorAndSize(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")
	secret := remoteFile(t, w, "myapp/dev.age")
	keyFile := remoteFile(t, w, "key.age")

	workFactor := func(data []byte, from, to string) []byte {
		old := []byte(" " + from + "\n")
		if !bytes.Contains(data, old) {
			t.Fatalf("the header has no work factor %s", from)
		}
		return bytes.Replace(data, old, []byte(" "+to+"\n"), 1)
	}
	large := bytes.Repeat([]byte{'x'}, crypt.MaxFileSize+1)

	secretCases := []struct {
		name string
		data []byte
		want string
	}{
		{"secret file with work factor 22", workFactor(secret, "10", "22"), "cannot use myapp/dev.age: damaged file: scrypt work factor too large: 22. " + outsideEnvs},
		{"secret file with work factor 11", workFactor(secret, "10", "11"), "cannot use myapp/dev.age: damaged file: scrypt work factor too large: 11. " + outsideEnvs},
		{"secret file above 1 MiB", large, "cannot use myapp/dev.age: file is larger than 1 MiB. " + outsideEnvs},
	}
	for _, c := range secretCases {
		t.Run(c.name, func(t *testing.T) {
			rawCommit(t, w.remote, "myapp/dev.age", c.data)
			childDidNotStart(t, w.a, w.dir, c.want)
			w.a.fails(w.dir, "", c.want, "list")
		})
	}

	keyCases := []struct {
		name string
		data []byte
		want string
	}{
		{"key.age with work factor 21", workFactor(keyFile, "18", "21"), "cannot use key.age: damaged file: scrypt work factor too large: 21. " + outsideEnvs},
		{"key.age with work factor 22", workFactor(keyFile, "18", "22"), "cannot use key.age: damaged file: scrypt work factor too large: 22. " + outsideEnvs},
		{"key.age above 1 MiB", large, "cannot use key.age: file is larger than 1 MiB. " + outsideEnvs},
	}
	for _, c := range keyCases {
		t.Run(c.name, func(t *testing.T) {
			rawCommit(t, w.remote, "key.age", c.data)
			b := newDevice(t)
			b.hidden = []string{passphrase}
			b.fails(b.home, "", c.want, "login", w.remote)
			if b.keychain != "" {
				t.Error("the login cached a key")
			}
		})
	}
}

// Threat: a person with write access corrupts a file to make the tool ask for the passphrase.
func TestThreat_CorruptedFile(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")
	valid := remoteFile(t, w, "myapp/dev.age")

	otherKey, err := crypt.NewStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	file := crypt.NewSecretFile("myapp", "dev")
	otherKeyFile, err := crypt.EncryptSecretFile(otherKey, file)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(index int) []byte {
		out := bytes.Clone(valid)
		out[index] ^= 1
		return out
	}
	// The wrapped file key is on the line after the "-> scrypt" line.
	wrappedKey := bytes.Index(valid, []byte("\n")) + 1
	wrappedKey += bytes.Index(valid[wrappedKey:], []byte("\n")) + 1

	cases := []struct {
		name string
		data []byte
	}{
		{"changed payload byte", flip(len(valid) - 1)},
		{"changed wrapped key", flip(wrappedKey)},
		{"truncated payload", valid[:len(valid)-1]},
		{"truncated header", valid[:wrappedKey]},
		{"empty file", nil},
		{"random bytes", bytes.Repeat([]byte{0xA7}, 300)},
		{"encrypted with another key", otherKeyFile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rawCommit(t, w.remote, "myapp/dev.age", c.data)
			keychain := w.a.keychain
			w.a.prompts = nil
			// The device is at a terminal, and no answer is queued. A
			// passphrase prompt fails the test.
			for _, args := range [][]string{{"list"}, {"rm", "API_KEY"}} {
				r := w.a.fails(w.dir, "", outsideEnvs, args...)
				if !strings.Contains(r.stderr, "myapp/dev.age") {
					t.Errorf("stderr = %q, want the name of the file", r.stderr)
				}
			}
			childDidNotStart(t, w.a, w.dir, outsideEnvs)
			if len(w.a.prompts) != 0 {
				t.Errorf("envs asked the user: %q", w.a.prompts)
			}
			if w.a.keychain != keychain {
				t.Error("the keychain entry changed")
			}
		})
	}
}

// Threat: a person with write access rewrites the store history.
func TestThreat_RewrittenHistory(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "old-value", "set", "ENVS_TEST_KEY")
	w.a.pipe(w.dir, "new-value", "set", "ENVS_TEST_KEY")
	w.a.pipe(w.dir, "second", "set", "ENVS_TEST_SECOND")

	// The remote goes back to the commit with the old value, with a new commit on it.
	raw := rawClone(t, w.remote)
	git(t, raw.Root, "reset", "--quiet", "--hard", "HEAD~2")
	rawWrite(t, raw, "note", []byte("x"))
	if err := raw.Commit(t.Context(), "outside envs", "note"); err != nil {
		t.Fatal(err)
	}
	git(t, raw.Root, "push", "--quiet", "--force", "origin", "main")
	head := git(t, w.remote, "rev-parse", "main")

	const warning = "warning: the remote history changed."
	t.Run("list warns and uses the local copy", func(t *testing.T) {
		r := w.a.ok(w.dir, "", "list")
		if !strings.Contains(r.stderr, warning) || !strings.Contains(r.stderr, outsideEnvs[4:]) || !strings.Contains(r.stderr, "local copy") {
			t.Errorf("stderr = %q", r.stderr)
		}
		if r.stdout != "ENVS_TEST_KEY\nENVS_TEST_SECOND\n" {
			t.Errorf("stdout = %q, want the local keys", r.stdout)
		}
	})
	t.Run("run warns and does not use the old value", func(t *testing.T) {
		if got := childValue(t, w.a, w.dir, "ENVS_TEST_KEY"); got != "new-value" {
			t.Errorf("child value = %q, want the local value", got)
		}
		exe, _ := os.Executable()
		r := w.a.ok(w.dir, "", "run", "--", exe, filepath.Join(t.TempDir(), "out"), "X", "0")
		if !strings.Contains(r.stderr, warning) {
			t.Errorf("stderr = %q", r.stderr)
		}
	})
	t.Run("a write stops", func(t *testing.T) {
		w.a.pipeFails(w.dir, "third", "the remote history changed. It does not continue the local history, so the store was changed outside envs", "set", "ENVS_TEST_THIRD")
		if git(t, w.remote, "rev-parse", "main") != head {
			t.Error("the write pushed a commit")
		}
		if got := w.a.values("myapp", "dev"); len(got) != 2 || got["ENVS_TEST_KEY"] != "new-value" {
			t.Error("the failed write changed the local copy")
		}
	})
}

// Threat: a downloaded project contains a link file that names one of the user's projects.
func TestThreat_UntrustedLinkFile(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")

	download := projectDir(t, "download")
	if err := link.Write(download, "myapp"); err != nil {
		t.Fatal(err)
	}
	folder, err := link.Canonical(download)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("stdin is not a terminal", func(t *testing.T) {
		w.a.terminal = false
		defer func() { w.a.terminal = true }()
		w.a.prompts = nil
		want := "the folder " + folder + " links to the project \"myapp\" and is not a trusted folder, and stdin is not a terminal"
		childDidNotStart(t, w.a, download, want)
		w.a.fails(download, "yes\n", want, "list")
		w.a.fails(download, "yes\n", want, "set", "API_KEY")
		if len(w.a.prompts) != 0 {
			t.Errorf("envs asked without a terminal: %q", w.a.prompts)
		}
	})
	for _, answer := range []string{"", "no", "y", "YES", " yes"} {
		t.Run("answer "+answer, func(t *testing.T) {
			w.a.prompts = nil
			w.a.lines = []string{answer}
			childDidNotStart(t, w.a, download, "stopped, because the answer was not \"yes\"")
			if len(w.a.prompts) != 1 || !strings.Contains(w.a.prompts[0], folder) || !strings.Contains(w.a.prompts[0], `"myapp"`) {
				t.Errorf("prompt = %q, want the folder and the project", w.a.prompts)
			}
		})
	}
	t.Run("a refused folder stays untrusted", func(t *testing.T) {
		trusted, err := link.IsTrusted(filepath.Join(w.a.home, ".envs"), folder, "myapp")
		if err != nil || trusted {
			t.Errorf("IsTrusted = %v, %v", trusted, err)
		}
	})
}

// Threat: a downloaded repository inside a trusted project has no link file.
func TestThreat_NestedRepository(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")

	const want = "no link file found. Run \"envs init\" in the project folder or pass --project"
	cases := []struct {
		name string
		git  func(t *testing.T, dir string)
	}{
		{"git init", func(t *testing.T, dir string) { git(t, dir, "init", "--quiet") }},
		{".git file of a worktree or submodule", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: ../elsewhere\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nested := filepath.Join(w.dir, "tmp", strings.ReplaceAll(c.name, " ", "-"))
			sub := filepath.Join(nested, "src")
			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			c.git(t, nested)
			w.a.prompts = nil
			for _, dir := range []string{nested, sub} {
				childDidNotStart(t, w.a, dir, want)
				w.a.fails(dir, "", want, "list")
			}
			if len(w.a.prompts) != 0 {
				t.Errorf("envs asked the user: %q", w.a.prompts)
			}
		})
	}
	t.Run("a folder of the project itself still works", func(t *testing.T) {
		sub := filepath.Join(w.dir, "tmp")
		if r := w.a.ok(sub, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
}

// Threat: a downloaded project contains a program with the same name as the dev command.
func TestThreat_CurrentFolderProgram(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")

	marker := filepath.Join(w.dir, "ran")
	name, content := "wrangler", "#!/bin/sh\necho ran > ran\n"
	if runtime.GOOS == "windows" {
		name, content = "wrangler.cmd", "@echo ran > ran\r\n"
	}
	if err := os.WriteFile(filepath.Join(w.dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	// The process starts programs relative to its current folder.
	t.Chdir(w.dir)
	// With this Windows variable the search skips the current folder, and
	// the program is "not on the PATH". The test covers the default search.
	const noCurrentDir = "NoDefaultCurrentDirectoryInExePath"
	if old, set := os.LookupEnv(noCurrentDir); set {
		os.Unsetenv(noCurrentDir)
		t.Cleanup(func() { os.Setenv(noCurrentDir, old) })
	}
	// Unix searches the current folder only for a "." or empty PATH entry.
	if runtime.GOOS != "windows" {
		t.Setenv("PATH", "."+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	t.Run("a bare name does not start the program", func(t *testing.T) {
		w.a.fails(w.dir, "", `the program "wrangler" is in the current folder, and envs does not start a program from the current folder. Use an explicit path such as ./wrangler`, "run", "--", "wrangler", "dev")
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("the program in the current folder started")
		}
	})
	t.Run("an explicit path starts the program", func(t *testing.T) {
		w.a.ok(w.dir, "", "run", "--", "./wrangler", "dev")
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("the program with an explicit path did not start")
		}
	})
}

// Threat: a name or URL contains characters that change a file path or a git command.
func TestThreat_HostileNames(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")
	head := git(t, w.remote, "rev-parse", "main")
	before := listTree(t, w.a.home)

	cases := []struct {
		name string
		want string
		args []string
	}{
		{"project with a parent folder", "invalid project name", []string{"set", "KEY", "--project", "../../outside"}},
		{"project with a separator", "invalid project name", []string{"set", "KEY", "--project", "a/b"}},
		{"project with a backslash", "invalid project name", []string{"set", "KEY", "--project", `..\outside`}},
		{"project that is an absolute path", "invalid project name", []string{"set", "KEY", "--project", filepath.Join(t.TempDir(), "x")}},
		{"project that is the git folder", "invalid project name", []string{"set", "KEY", "--project", ".git"}},
		{"project that looks like a flag", "invalid project name", []string{"set", "KEY", "--project", "--force"}},
		{"project in uppercase", "invalid project name", []string{"set", "KEY", "--project", "MyApp"}},
		{"project with a line break", "invalid project name", []string{"set", "KEY", "--project", "a\nb"}},
		{"environment with a parent folder", "invalid environment name", []string{"set", "KEY", "--env", "../../outside"}},
		{"environment with two dots", "invalid environment name", []string{"set", "KEY", "--env", "a..b"}},
		{"environment that looks like a flag", "invalid environment name", []string{"list", "--env", "-x"}},
		{"key with an equals sign", "invalid key name", []string{"set", "A=B"}},
		{"key with a line break", "invalid key name", []string{"set", "A\nB=1"}},
		{"key that looks like a flag", "envs help", []string{"rm", "--force"}},
		{"init with a parent folder", "invalid project name", []string{"init", "../outside"}},
		{"run with a hostile project", "invalid project name", []string{"run", "--project", "../x", "--", "git", "version"}},
		{"import with a hostile environment", "invalid environment name", []string{"import", "--env", "x/../y", "file"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w.a.pipeFails(w.dir, "value", c.want, c.args...)
		})
	}

	urls := []struct {
		url  string
		want string
	}{
		{"-oProxyCommand=calc", "the repository URL starts with \"-\""},
		{"--upload-pack=calc", "the repository URL starts with \"-\""},
		{"ext::sh -c calc", "the repository URL uses remote helper syntax"},
		{"https://user:token@example.com/store.git", "the repository URL contains a user name or token, and git would store it in plaintext"},
		{"https://token@example.com/store.git", "the repository URL contains a user name or token"},
		{"file:///tmp/store.git", "the repository URL uses the scheme \"file\""},
	}
	for _, c := range urls {
		t.Run("login "+c.url, func(t *testing.T) {
			d := newDevice(t)
			d.fails(d.home, "", c.want, "login", c.url)
			if _, err := os.Stat(filepath.Join(d.home, ".envs")); err == nil {
				t.Error("the login created ~/.envs")
			}
		})
	}

	t.Run("a link file with a hostile name", func(t *testing.T) {
		dir := projectDir(t, "download")
		if err := os.WriteFile(filepath.Join(dir, ".envs.json"), []byte(`{"project":"../../outside"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		w.a.fails(dir, "", "invalid link file", "list")
	})
	t.Run("nothing changed", func(t *testing.T) {
		if git(t, w.remote, "rev-parse", "main") != head {
			t.Error("a rejected command pushed a commit")
		}
		if after := listTree(t, w.a.home); after != before {
			t.Errorf("a rejected command changed the files:\n%s\nwant:\n%s", after, before)
		}
	})
}

// listTree returns the paths below root, without the content of .git folders.
func listTree(t *testing.T, root string) string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(paths, "\n")
}

// Threat: a value appears on screen, in scrollback, in logs, or in shell history.
func TestThreat_ValueDisclosure(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	const secret = "s3cret-value-0001"

	var outputs []string
	record := func(r result) {
		outputs = append(outputs, r.stdout, r.stderr)
	}

	t.Run("a terminal gets a hidden prompt", func(t *testing.T) {
		d.prompts = nil
		d.hidden = []string{secret}
		record(d.ok(dir, "stdin is not used", "set", "API_KEY"))
		if len(d.prompts) != 1 || d.prompts[0] != "Value of API_KEY: " {
			t.Errorf("prompts = %q, want one hidden prompt", d.prompts)
		}
		if d.values("myapp", "dev")["API_KEY"] != secret {
			t.Error("the value was not stored")
		}
	})
	t.Run("no command takes a value as an argument", func(t *testing.T) {
		head := git(t, w.remote, "rev-parse", "main")
		r := d.fails(dir, "", "envs set takes one key name and no value", "set", "OTHER", "argument-value")
		record(r)
		if strings.Contains(r.stderr, "argument-value") {
			t.Errorf("stderr repeats the argument: %q", r.stderr)
		}
		if git(t, w.remote, "rev-parse", "main") != head {
			t.Error("the command stored the argument")
		}
	})
	t.Run("no command shows a value", func(t *testing.T) {
		for _, command := range []string{"show", "get", "print", "export", "cat", "dump"} {
			record(d.fails(dir, "", "unknown command", command, "API_KEY"))
		}
		if r := d.ok(dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("list printed %q, want the key name only", r.stdout)
		}
	})
	t.Run("no output contains the value", func(t *testing.T) {
		source := filepath.Join(dir, "vars")
		if err := os.WriteFile(source, []byte("IMPORTED="+secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		record(d.ok(dir, "", "help"))
		record(d.ok(dir, "", "list"))
		record(d.ok(dir, "", "list", "--offline"))
		record(d.ok(dir, "", "import", "vars"))
		record(d.pipe(dir, secret, "set", "PIPED"))
		record(d.pipeFails(dir, secret, "differs only by case", "set", "piped"))
		record(d.pipeFails(dir, secret+"\x00", "NUL byte", "set", "BAD"))
		record(d.ok(dir, "", "rm", "PIPED"))
		record(d.fails(dir, "", "is not on the PATH", "run", "--", "envs-program-that-does-not-exist"))
		if err := os.WriteFile(source, []byte("BAD-KEY="+secret+"\nline with "+secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		record(d.fails(dir, "", "line 1", "import", "vars"))
		if err := os.Remove(source); err != nil {
			t.Fatal(err)
		}

		for _, text := range append(outputs, d.prompts...) {
			if strings.Contains(text, secret) {
				t.Errorf("output contains the value: %q", text)
			}
		}
		if log := git(t, w.remote, "log", "--format=%B", "main"); strings.Contains(log, secret) {
			t.Error("a commit message contains the value")
		}
	})
}

// Threat: a plaintext copy stays on disk.
func TestThreat_PlaintextOnDisk(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	const first, second, third = "s3cret-value-0001", "s3cret-value-0002", "s3cret-value-0003"

	// The temporary folder of the process is inside a folder that the test checks.
	scratch := t.TempDir()
	for _, name := range []string{"TMP", "TEMP", "TMPDIR"} {
		t.Setenv(name, scratch)
	}

	d.hidden = []string{first}
	d.ok(dir, "", "set", "ENVS_TEST_KEY")
	d.pipe(dir, second, "set", "SECOND")
	source := filepath.Join(dir, ".dev.vars")
	if err := os.WriteFile(source, []byte("THIRD="+third+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := d.ok(dir, "", "import", ".dev.vars")
	if got := childValue(t, d, dir, "ENVS_TEST_KEY"); got != first {
		t.Fatalf("child value = %q", got)
	}
	d.ok(dir, "", "list")
	d.ok(dir, "", "rm", "SECOND")

	t.Run("import warns about the source file", func(t *testing.T) {
		if !strings.Contains(r.stderr, "warning: .dev.vars still exists and holds the values in plaintext. Delete it. A deleted file is recoverable from the disk.") {
			t.Errorf("stderr = %q", r.stderr)
		}
		if _, err := os.Stat(source); err != nil {
			t.Error("import deleted the source file")
		}
	})
	t.Run("envs creates no plaintext file", func(t *testing.T) {
		if err := os.Remove(source); err != nil {
			t.Fatal(err)
		}
		texts := []string{first, second, third, d.storeKey(), passphrase}
		assertNotOnDisk(t, d.home, texts...)
		assertNotOnDisk(t, dir, texts...)
		assertNotOnDisk(t, scratch, texts...)
		assertNotOnDisk(t, w.remote, texts...)
	})
	t.Run("the keychain holds the store key and the hash only", func(t *testing.T) {
		key, hash, _ := strings.Cut(d.keychain, ":")
		if !crypt.ValidStoreKey(key) || hash != crypt.Hash(readFile(t, filepath.Join(d.storeDir(), "key.age"))) {
			t.Error("the keychain entry is not <store key>:<hash of key.age>")
		}
		if strings.Contains(d.keychain, passphrase) {
			t.Error("the keychain holds the passphrase")
		}
	})
}
