package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/link"
	"github.com/lminii/envs/internal/store"
)

func TestLoginFirstDevice(t *testing.T) {
	isolate(t)
	remote := bareRepo(t)
	d := newDevice(t)
	d.hidden = []string{passphrase, passphrase}
	r := d.ok(d.home, "", "login", remote)

	if !strings.Contains(r.stdout, "Logged in") {
		t.Errorf("stdout = %q", r.stdout)
	}
	if len(d.prompts) != 2 {
		t.Errorf("prompts = %q, want two passphrase prompts", d.prompts)
	}
	if !crypt.ValidStoreKey(d.storeKey()) {
		t.Error("the keychain has no store key")
	}
	if strings.Contains(d.keychain, passphrase) {
		t.Error("the keychain holds the passphrase")
	}
	if got := git(t, remote, "log", "--format=%s", "main"); got != "envs login" {
		t.Errorf("remote log = %q", got)
	}
	if got := git(t, remote, "ls-tree", "--name-only", "main"); got != ".gitattributes\nkey.age" {
		t.Errorf("remote files = %q", got)
	}
	if got := git(t, remote, "show", "main:.gitattributes"); got != "*.age binary" {
		t.Errorf(".gitattributes = %q", got)
	}
	key, err := crypt.DecryptKeyFile(passphrase, readFile(t, filepath.Join(d.storeDir(), "key.age")))
	if err != nil || key != d.storeKey() {
		t.Errorf("key.age does not hold the cached store key: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(d.home, ".envs"))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("~/.envs mode = %v, %v, want 0700", info.Mode().Perm(), err)
		}
	}
}

func TestLoginSecondDevice(t *testing.T) {
	w := newWorld(t)
	b := newDevice(t)
	b.hidden = []string{passphrase}
	b.ok(b.home, "", "login", w.remote)
	if len(b.prompts) != 1 {
		t.Errorf("prompts = %q, want one passphrase prompt", b.prompts)
	}
	if b.storeKey() != w.a.storeKey() {
		t.Error("the two devices have different store keys")
	}
}

func TestLoginErrors(t *testing.T) {
	isolate(t)
	remote := bareRepo(t)

	noStore := func(t *testing.T, d *device) {
		t.Helper()
		if _, err := os.Stat(d.storeDir()); err == nil {
			t.Error("a failed login left a clone")
		}
		if d.keychain != "" {
			t.Error("a failed login left a key in the keychain")
		}
	}

	t.Run("no URL", func(t *testing.T) {
		newDevice(t).fails(t.TempDir(), "", "envs login <repo-url>", "login")
	})
	t.Run("invalid URL", func(t *testing.T) {
		d := newDevice(t)
		d.fails(d.home, "", "user name or token", "login", "https://me:token@example.com/store.git")
		noStore(t, d)
	})
	t.Run("stdin is not a terminal", func(t *testing.T) {
		d := newDevice(t)
		d.pipeFails(d.home, passphrase+"\n", "stdin is not a terminal", "login", remote)
		noStore(t, d)
	})
	t.Run("repository does not exist", func(t *testing.T) {
		d := newDevice(t)
		d.fails(d.home, "", "git clone", "login", filepath.Join(t.TempDir(), "missing.git"))
		noStore(t, d)
	})
	t.Run("passphrase with 15 characters", func(t *testing.T) {
		d := newDevice(t)
		// 15 characters in 16 bytes.
		d.hidden = []string{"fifteen-chars-ä"}
		d.fails(d.home, "", "fewer than 16 characters", "login", remote)
		noStore(t, d)
	})
	t.Run("passphrases are not equal", func(t *testing.T) {
		d := newDevice(t)
		d.hidden = []string{passphrase, passphrase + "x"}
		d.fails(d.home, "", "not equal", "login", remote)
		noStore(t, d)
	})

	first := newDevice(t)
	first.login(remote, true)

	t.Run("store exists on the device", func(t *testing.T) {
		first.fails(first.home, "", "envs logout", "login", remote)
		if _, err := os.Stat(first.storeDir()); err != nil {
			t.Error("the login removed the store")
		}
	})
	t.Run("wrong passphrase, then the correct one", func(t *testing.T) {
		d := newDevice(t)
		d.hidden = []string{"wrong horse battery staple"}
		d.fails(d.home, "", "passphrase is wrong", "login", remote)
		noStore(t, d)
		d.login(remote, false)
	})
}

func TestLoginFirstPushRejected(t *testing.T) {
	isolate(t)
	remote := bareRepo(t)
	d := newDevice(t)
	d.hidden = []string{passphrase, passphrase}
	// Another device creates the store between the clone and the push.
	d.onHidden = func() { rawCommit(t, remote, "key.age", []byte("the key of another device")) }
	d.fails(d.home, "", "Run \"envs login\" again", "login", remote)

	if _, err := os.Stat(d.storeDir()); err == nil {
		t.Error("the clone was not deleted")
	}
	if d.keychain != "" {
		t.Error("the new key is in the keychain")
	}
	if got := git(t, remote, "log", "--format=%s", "main"); got != "outside envs" {
		t.Errorf("remote log = %q, want only the commit of the other device", got)
	}
}

func TestInit(t *testing.T) {
	isolate(t)
	remote := bareRepo(t)
	d := newDevice(t)

	t.Run("no store on the device", func(t *testing.T) {
		d.fails(projectDir(t, "myapp"), "", "envs login <repo-url>", "init")
	})
	d.login(remote, true)

	linked := func(t *testing.T, dir, project string) {
		t.Helper()
		if got := string(readFile(t, filepath.Join(dir, ".envs.json"))); got != `{"project":"`+project+`"}`+"\n" {
			t.Errorf("link file = %q", got)
		}
		folder, err := link.Canonical(dir)
		if err != nil {
			t.Fatal(err)
		}
		trusted, err := link.IsTrusted(filepath.Join(d.home, ".envs"), folder, project)
		if err != nil || !trusted {
			t.Errorf("the folder is not trusted: %v", err)
		}
	}

	t.Run("default name is the folder name in lowercase", func(t *testing.T) {
		dir := projectDir(t, "My-App")
		r := d.ok(dir, "", "init")
		linked(t, dir, "my-app")
		if !strings.Contains(r.stdout, `"my-app"`) {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("folder name is not a valid name", func(t *testing.T) {
		dir := projectDir(t, "my app")
		d.fails(dir, "", "envs init <name>", "init")
		if _, err := os.Stat(filepath.Join(dir, ".envs.json")); err == nil {
			t.Error("a failed init wrote a link file")
		}
	})
	t.Run("explicit name", func(t *testing.T) {
		dir := projectDir(t, "my app")
		d.ok(dir, "", "init", "other")
		linked(t, dir, "other")
	})
	t.Run("invalid explicit name", func(t *testing.T) {
		d.fails(projectDir(t, "x"), "", "invalid project name", "init", "../other")
	})

	dir := projectDir(t, "myapp")
	d.ok(dir, "", "init")
	d.pipe(dir, "value\n", "set", "API_KEY")

	t.Run("project exists, answer yes", func(t *testing.T) {
		other := projectDir(t, "myapp")
		d.lines = []string{"yes"}
		d.ok(other, "", "init")
		linked(t, other, "myapp")
		if last := d.prompts[len(d.prompts)-1]; !strings.Contains(last, `The project "myapp" exists in the store`) {
			t.Errorf("prompt = %q", last)
		}
	})
	for _, answer := range []string{"", "y", "Yes", "YES", "yes ", "no"} {
		t.Run("project exists, answer "+answer, func(t *testing.T) {
			other := projectDir(t, "myapp")
			d.lines = []string{answer}
			d.fails(other, "", "the answer was not \"yes\"", "init")
			if _, err := os.Stat(filepath.Join(other, ".envs.json")); err == nil {
				t.Error("init wrote a link file without confirmation")
			}
		})
	}
	t.Run("project exists, stdin is not a terminal", func(t *testing.T) {
		d.pipeFails(projectDir(t, "myapp"), "yes\n", "stdin is not a terminal", "init")
	})
}

func TestSetListRm(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir

	t.Run("list before the first set", func(t *testing.T) {
		d.fails(dir, "", "envs set <KEY>", "list")
	})

	r := d.pipe(dir, "s3cret-one\n", "set", "API_KEY")
	if r.stdout != "Set API_KEY in myapp/dev\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	d.pipe(dir, "s3cret-two", "set", "DB_PASSWORD")
	d.pipe(dir, "prod-value\r\n", "set", "API_KEY", "--env", "prod")
	d.pipe(dir, "other-value\n", "set", "--project", "other", "TOKEN")

	t.Run("values", func(t *testing.T) {
		if got := d.values("myapp", "dev"); len(got) != 2 || got["API_KEY"] != "s3cret-one" || got["DB_PASSWORD"] != "s3cret-two" {
			t.Errorf("myapp/dev has wrong values")
		}
		if got := d.values("myapp", "prod"); len(got) != 1 || got["API_KEY"] != "prod-value" {
			t.Errorf("myapp/prod has wrong values")
		}
		if got := d.values("other", "dev"); len(got) != 1 || got["TOKEN"] != "other-value" {
			t.Errorf("other/dev has wrong values")
		}
	})
	t.Run("list prints sorted key names", func(t *testing.T) {
		if r := d.ok(dir, "", "list"); r.stdout != "API_KEY\nDB_PASSWORD\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if r := d.ok(dir, "", "list", "--env", "prod", "--offline"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("commit messages", func(t *testing.T) {
		got := git(t, w.remote, "log", "--format=%s", "-3", "main")
		want := "envs set other/dev TOKEN\nenvs set myapp/prod API_KEY\nenvs set myapp/dev DB_PASSWORD"
		if got != want {
			t.Errorf("remote log = %q, want %q", got, want)
		}
	})
	t.Run("no unpushed commits", func(t *testing.T) {
		if local, remoteHead := git(t, d.storeDir(), "rev-parse", "HEAD"), git(t, w.remote, "rev-parse", "main"); local != remoteHead {
			t.Errorf("local HEAD %s differs from the remote %s", local, remoteHead)
		}
	})
	t.Run("stdin value keeps all other blanks", func(t *testing.T) {
		d.pipe(dir, "  two lines\n\twith blanks  \n\n", "set", "MULTI")
		if got := d.values("myapp", "dev")["MULTI"]; got != "  two lines\n\twith blanks  \n" {
			t.Errorf("value = %q", got)
		}
		d.pipe(dir, "", "rm", "MULTI")
	})
	t.Run("hidden prompt on a terminal", func(t *testing.T) {
		d.hidden = []string{"typed value"}
		d.ok(dir, "ignored stdin", "set", "TYPED")
		if last := d.prompts[len(d.prompts)-1]; last != "Value of TYPED: " {
			t.Errorf("prompt = %q", last)
		}
		if got := d.values("myapp", "dev")["TYPED"]; got != "typed value" {
			t.Errorf("value = %q", got)
		}
		d.ok(dir, "", "rm", "TYPED")
	})

	errorCases := []struct {
		name  string
		stdin string
		want  string
		args  []string
	}{
		{"empty value", "", "the value is empty", []string{"set", "EMPTY"}},
		{"only a line ending", "\r\n", "the value is empty", []string{"set", "EMPTY"}},
		{"NUL byte", "s3c\x00ret\n", "NUL byte", []string{"set", "BAD"}},
		{"not UTF-8", "s3c\xffret\n", "not valid UTF-8", []string{"set", "BAD"}},
		{"key differs only by case", "s3cret\n", `differs only by case from the key "API_KEY"`, []string{"set", "Api_Key"}},
		{"invalid key name", "s3cret\n", "invalid key name", []string{"set", "API-KEY"}},
		{"value as an argument", "", "takes one key name and no value", []string{"set", "API_KEY", "s3cret"}},
		{"no key", "s3cret\n", "takes one key name and no value", []string{"set"}},
		{"invalid environment", "s3cret\n", "invalid environment name", []string{"set", "API_KEY", "--env", "../x"}},
		{"invalid project", "s3cret\n", "invalid project name", []string{"set", "API_KEY", "--project", "a/b"}},
		{"unknown flag", "s3cret\n", "envs help", []string{"set", "API_KEY", "--show"}},
		{"rm of a missing key", "", `has no key "MISSING"`, []string{"rm", "MISSING"}},
		{"rm in a missing environment", "", `has no key "API_KEY"`, []string{"rm", "API_KEY", "--env", "staging"}},
		{"rm without a key", "", "envs rm <KEY>", []string{"rm"}},
		{"list with an argument", "", "takes no arguments", []string{"list", "API_KEY"}},
		{"list of a missing environment", "", "no values for myapp/staging", []string{"list", "--env", "staging"}},
		{"unknown command", "", "unknown command", []string{"show", "API_KEY"}},
	}
	before := git(t, w.remote, "rev-parse", "main")
	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			r := d.pipeFails(dir, c.stdin, c.want, c.args...)
			if strings.Contains(r.stderr, "s3c") || strings.Contains(r.stdout, "s3c") {
				t.Errorf("the output contains a value: %q %q", r.stdout, r.stderr)
			}
		})
	}
	t.Run("failed commands change nothing", func(t *testing.T) {
		if after := git(t, w.remote, "rev-parse", "main"); after != before {
			t.Error("a failed command pushed a commit")
		}
		if out := git(t, d.storeDir(), "status", "--porcelain"); out != "" {
			t.Errorf("the clone is not clean: %q", out)
		}
	})

	t.Run("rm", func(t *testing.T) {
		r := d.ok(dir, "", "rm", "DB_PASSWORD")
		if r.stdout != "Removed DB_PASSWORD from myapp/dev\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if r := d.ok(dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if got := git(t, w.remote, "log", "--format=%s", "-1", "main"); got != "envs rm myapp/dev DB_PASSWORD" {
			t.Errorf("commit message = %q", got)
		}
	})
}

func TestNoArguments(t *testing.T) {
	isolate(t)
	d := newDevice(t)
	if r := d.run(t.TempDir(), ""); r.code == 0 || !strings.Contains(r.stderr, "Usage:") {
		t.Errorf("no arguments: code %d, stderr %q", r.code, r.stderr)
	}
	if r := d.ok(t.TempDir(), "", "help"); !strings.Contains(r.stdout, "Usage:") {
		t.Errorf("help: stdout %q", r.stdout)
	}
}

func TestImport(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	d.pipe(dir, "old\n", "set", "API_KEY")
	d.pipe(dir, "kept\n", "set", "KEPT")

	source := filepath.Join(dir, ".dev.vars")
	content := "# local secrets\r\nAPI_KEY=new$HOME\r\nexport DB_URL=\"postgres://u:p@host/db?x=${Y}\"\r\nTOKEN='a b'\r\n"
	if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	before := git(t, w.remote, "rev-list", "--count", "main")

	r := d.pipe(dir, "", "import", ".dev.vars")
	if r.stdout != "Imported 3 keys into myapp/dev\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	if !strings.Contains(r.stderr, ".dev.vars still exists") || !strings.Contains(r.stderr, "recoverable") {
		t.Errorf("stderr has no warning about the source file: %q", r.stderr)
	}
	if string(readFile(t, source)) != content {
		t.Error("import changed the source file")
	}
	want := map[string]string{
		"API_KEY": "new$HOME",
		"DB_URL":  "postgres://u:p@host/db?x=${Y}",
		"TOKEN":   "a b",
		"KEPT":    "kept",
	}
	got := d.values("myapp", "dev")
	if len(got) != len(want) {
		t.Errorf("the file has %d keys, want %d", len(got), len(want))
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s has a wrong value", key)
		}
	}
	if after := git(t, w.remote, "rev-list", "--count", "main"); after != addOne(t, before) {
		t.Errorf("import made %s commits from %s, want one", after, before)
	}
	if msg := git(t, w.remote, "log", "--format=%s", "-1", "main"); msg != "envs import myapp/dev" {
		t.Errorf("commit message = %q", msg)
	}

	errorCases := []struct {
		name    string
		content string
		want    string
	}{
		{"invalid key name", "GOOD=1\nBAD-KEY=s3cret\n", "bad.env: line 2: the key name is not valid"},
		{"NUL byte", "BAD=s3c\x00ret\n", "bad.env: line 1: the value contains a NUL byte"},
		{"case of an existing key", "GOOD=1\napi_key=s3cret\n", `bad.env: line 2: the key "api_key" differs only by case from the key "API_KEY"`},
		{"case inside the file", "NEW_KEY=1\nNew_Key=s3cret\n", `bad.env: line 2: the key "New_Key" differs only by case from the key "NEW_KEY"`},
		{"no keys", "# nothing\n", "bad.env has no keys"},
	}
	head := git(t, w.remote, "rev-parse", "main")
	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "bad.env"), []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			r := d.pipeFails(dir, "", c.want, "import", "bad.env")
			if strings.Contains(r.stderr, "s3c") {
				t.Errorf("stderr contains a value: %q", r.stderr)
			}
			if git(t, w.remote, "rev-parse", "main") != head {
				t.Error("a failed import pushed a commit")
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		d.pipeFails(dir, "", "cannot read the file", "import", "missing.env")
	})
}

func addOne(t *testing.T, n string) string {
	t.Helper()
	digits := []byte(n)
	for i := len(digits) - 1; i >= 0; i-- {
		if digits[i] != '9' {
			digits[i]++
			return string(digits)
		}
		digits[i] = '0'
	}
	return "1" + string(digits)
}

func TestRun(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	value := "s3cret \"quoted\" $HOME %PATH%\nline2"
	d.pipe(dir, value, "set", "ENVS_TEST_KEY")
	d.pipe(dir, "prod-value", "set", "ENVS_TEST_KEY", "--env", "prod")

	t.Run("injects the stored value", func(t *testing.T) {
		if got := childValue(t, d, dir, "ENVS_TEST_KEY"); got != value {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("stored value overrides the parent", func(t *testing.T) {
		t.Setenv("ENVS_TEST_KEY", "parent")
		if got := childValue(t, d, dir, "ENVS_TEST_KEY"); got != value {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("parent variables stay", func(t *testing.T) {
		t.Setenv("ENVS_TEST_PARENT", "parent")
		if got := childValue(t, d, dir, "ENVS_TEST_PARENT"); got != "parent" {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("environment flag", func(t *testing.T) {
		if got := childValue(t, d, dir, "ENVS_TEST_KEY", "--env", "prod", "--offline"); got != "prod-value" {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("from a subfolder", func(t *testing.T) {
		sub := filepath.Join(dir, "src", "deep")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := childValue(t, d, sub, "ENVS_TEST_KEY"); got != value {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("exit code of the child", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(helperEnv, "1")
		r := d.run(dir, "", "run", "--", exe, filepath.Join(t.TempDir(), "out"), "X", "42")
		if r.code != 42 {
			t.Errorf("exit code = %d, want 42", r.code)
		}
	})
	t.Run("child flags stay with the child", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(helperEnv, "1")
		// "--env" after the program is an argument of the child. The helper reads it as the variable name.
		out := filepath.Join(t.TempDir(), "out")
		d.ok(dir, "", "run", exe, out, "--env", "0")
		if got := string(readFile(t, out)); got != "" {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("no command", func(t *testing.T) {
		d.fails(dir, "", "envs run -- <command>", "run", "--")
	})
	t.Run("program not found", func(t *testing.T) {
		r := d.fails(dir, "", "is not on the PATH", "run", "--", "envs-program-that-does-not-exist")
		if strings.Contains(r.stderr, "s3cret") {
			t.Errorf("stderr contains a value: %q", r.stderr)
		}
	})
	t.Run("no link file", func(t *testing.T) {
		d.fails(projectDir(t, "unlinked"), "", "no link file found. Run \"envs init\" in the project folder or pass --project", "run", "--", "git", "version")
	})
}

func TestSyncFailureOnRead(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	d.pipe(dir, "value", "set", "ENVS_TEST_KEY")
	if err := os.RemoveAll(w.remote); err != nil {
		t.Fatal(err)
	}

	t.Run("list warns and uses the local copy", func(t *testing.T) {
		r := d.ok(dir, "", "list")
		if r.stdout != "ENVS_TEST_KEY\n" || !strings.Contains(r.stderr, "warning: cannot sync the store") || !strings.Contains(r.stderr, "local copy") {
			t.Errorf("stdout = %q, stderr = %q", r.stdout, r.stderr)
		}
	})
	t.Run("offline does not sync", func(t *testing.T) {
		if r := d.ok(dir, "", "list", "--offline"); r.stderr != "" {
			t.Errorf("stderr = %q", r.stderr)
		}
	})
	t.Run("run uses the local copy", func(t *testing.T) {
		if got := childValue(t, d, dir, "ENVS_TEST_KEY"); got != "value" {
			t.Errorf("child value = %q", got)
		}
	})
	t.Run("a write stops", func(t *testing.T) {
		d.pipeFails(dir, "new", "A write needs the remote", "set", "ENVS_TEST_KEY")
		if got := d.values("myapp", "dev")["ENVS_TEST_KEY"]; got != "value" {
			t.Error("a failed write changed the local copy")
		}
		if out := git(t, d.storeDir(), "status", "--porcelain"); out != "" {
			t.Errorf("the clone is not clean: %q", out)
		}
	})
}

func TestTrustedFolders(t *testing.T) {
	w := newWorld(t)
	d := w.a
	d.pipe(w.dir, "value", "set", "API_KEY")

	// A second checkout of the project, with the committed link file.
	checkout := projectDir(t, "checkout")
	if err := link.Write(checkout, "myapp"); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(checkout, "src")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	canonical, err := link.Canonical(checkout)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("--project needs no confirmation", func(t *testing.T) {
		if r := d.pipe(sub, "", "list", "--project", "myapp"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("answer no", func(t *testing.T) {
		d.lines = []string{"no"}
		d.fails(sub, "", "the answer was not \"yes\"", "list")
	})
	t.Run("answer yes from a subfolder", func(t *testing.T) {
		d.prompts = nil
		d.lines = []string{"yes"}
		if r := d.ok(sub, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if len(d.prompts) != 1 || !strings.Contains(d.prompts[0], canonical) || !strings.Contains(d.prompts[0], `"myapp"`) {
			t.Errorf("prompt = %q, want the folder of the link file %q and the project", d.prompts, canonical)
		}
		if strings.Contains(d.prompts[0], sub) {
			t.Errorf("the prompt shows the current folder: %q", d.prompts[0])
		}
	})
	t.Run("the folder stays trusted", func(t *testing.T) {
		d.pipe(checkout, "", "list")
		d.pipe(sub, "", "list")
	})
	t.Run("a new project name in a trusted folder asks again", func(t *testing.T) {
		if err := link.Write(checkout, "other"); err != nil {
			t.Fatal(err)
		}
		d.pipeFails(checkout, "", "is not a trusted folder", "list")
	})
	t.Run("invalid link file", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(checkout, ".envs.json"), []byte(`{"project":"../x"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		d.fails(checkout, "", "invalid link file", "list")
	})
}

func TestTwoDevices(t *testing.T) {
	w := newWorld(t)
	a, dirA := w.a, w.dir
	a.pipe(dirA, "from-a", "set", "ENVS_TEST_KEY")

	b, dirB := w.second(t)
	t.Run("a new device gets the values", func(t *testing.T) {
		if got := childValue(t, b, dirB, "ENVS_TEST_KEY"); got != "from-a" {
			t.Errorf("child value on B = %q", got)
		}
	})
	t.Run("a value from B reaches A on the next run", func(t *testing.T) {
		b.pipe(dirB, "from-b", "set", "ENVS_TEST_KEY")
		b.pipe(dirB, "second", "set", "ENVS_TEST_SECOND")
		if got := childValue(t, a, dirA, "ENVS_TEST_KEY"); got != "from-b" {
			t.Errorf("child value on A = %q", got)
		}
		if r := a.ok(dirA, "", "list", "--offline"); r.stdout != "ENVS_TEST_KEY\nENVS_TEST_SECOND\n" {
			t.Errorf("list on A = %q", r.stdout)
		}
	})
	t.Run("writes from both devices keep all keys", func(t *testing.T) {
		a.pipe(dirA, "a", "set", "ENVS_TEST_A")
		b.pipe(dirB, "b", "set", "ENVS_TEST_B")
		a.pipe(dirA, "", "rm", "ENVS_TEST_SECOND")
		if r := b.ok(dirB, "", "list"); r.stdout != "ENVS_TEST_A\nENVS_TEST_B\nENVS_TEST_KEY\n" {
			t.Errorf("list on B = %q", r.stdout)
		}
	})
	t.Run("an overwrite is recoverable from git history", func(t *testing.T) {
		commits := strings.Fields(git(t, w.remote, "log", "--format=%H", "--grep=envs set myapp/dev ENVS_TEST_KEY", "main"))
		first := commits[len(commits)-1]
		old, err := exec.Command("git", "-C", w.remote, "cat-file", "blob", first+":myapp/dev.age").Output()
		if err != nil {
			t.Fatal(err)
		}
		file, err := crypt.DecryptSecretFile(a.storeKey(), old, "myapp", "dev")
		if err != nil || file.Values["ENVS_TEST_KEY"] != "from-a" {
			t.Errorf("the first version is not recoverable: %v", err)
		}
	})
}

func TestWriteRetry(t *testing.T) {
	newSession := func(t *testing.T) (*world, *session, target) {
		w := newWorld(t)
		w.a.pipe(w.dir, "one", "set", "FIRST")
		app := &App{Stdout: os.Stdout, Stderr: os.Stderr, Home: w.a.home, IsTerminal: func() bool { return false }}
		w.a.loadKeychain()
		se, err := app.open()
		if err != nil {
			t.Fatal(err)
		}
		return w, se, target{"myapp", "dev"}
	}
	// otherDevice pushes a change of another key between the sync and the push.
	otherDevice := func(t *testing.T, w *world, key string) {
		t.Helper()
		raw := rawClone(t, w.remote)
		path := filepath.Join(raw.Root, "myapp", "dev.age")
		file, err := crypt.DecryptSecretFile(w.a.storeKey(), readFile(t, path), "myapp", "dev")
		if err != nil {
			t.Fatal(err)
		}
		file.Values[key] = "other"
		data, err := crypt.EncryptSecretFile(w.a.storeKey(), file)
		if err != nil {
			t.Fatal(err)
		}
		rawWrite(t, raw, "myapp/dev.age", data)
		rawPush(t, raw, "envs set myapp/dev "+key, "myapp/dev.age")
	}

	t.Run("one rejected push", func(t *testing.T) {
		w, se, tg := newSession(t)
		attempts := 0
		err := se.write(t.Context(), tg, "envs set myapp/dev MINE", func(file *crypt.SecretFile) error {
			attempts++
			if attempts == 1 {
				otherDevice(t, w, "THEIRS")
			}
			file.Values["MINE"] = "mine"
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if attempts != 2 {
			t.Errorf("attempts = %d, want 2", attempts)
		}
		got := w.a.values("myapp", "dev")
		if len(got) != 3 || got["FIRST"] != "one" || got["THEIRS"] != "other" || got["MINE"] != "mine" {
			t.Errorf("the file lost a change: %d keys", len(got))
		}
		if local, remoteHead := git(t, w.a.storeDir(), "rev-parse", "HEAD"), git(t, w.remote, "rev-parse", "main"); local != remoteHead {
			t.Error("the local clone differs from the remote")
		}
	})
	t.Run("three rejected pushes", func(t *testing.T) {
		w, se, tg := newSession(t)
		attempts := 0
		err := se.write(t.Context(), tg, "envs set myapp/dev MINE", func(file *crypt.SecretFile) error {
			attempts++
			otherDevice(t, w, "THEIRS"+strings.Repeat("_", attempts))
			file.Values["MINE"] = "mine"
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "rejected the push 3 times") {
			t.Fatalf("error = %v, want the retry limit error", err)
		}
		if attempts != 3 {
			t.Errorf("attempts = %d, want 3", attempts)
		}
		if _, ok := w.a.values("myapp", "dev")["MINE"]; ok {
			t.Error("the rejected change is in the local clone")
		}
		if local, remoteHead := git(t, w.a.storeDir(), "rev-parse", "HEAD"), git(t, w.remote, "rev-parse", "main"); local != remoteHead {
			t.Error("the local clone keeps an unpushed commit")
		}
	})
}

func TestKeyRotationOnAnotherDevice(t *testing.T) {
	const newPassphrase = "a new and longer passphrase"

	// rotate does what "envs rotate" does on another device: a new store key,
	// a new key.age, and all files encrypted again, in one commit.
	rotate := func(t *testing.T, w *world) (newKey string) {
		t.Helper()
		raw := rawClone(t, w.remote)
		newKey, err := crypt.NewStoreKey()
		if err != nil {
			t.Fatal(err)
		}
		files, err := raw.SecretFiles()
		if err != nil {
			t.Fatal(err)
		}
		paths := []string{store.KeyFileName}
		for _, rel := range files {
			project, environment := filepath.Base(filepath.Dir(rel)), strings.TrimSuffix(filepath.Base(rel), ".age")
			file, err := crypt.DecryptSecretFile(w.a.storeKey(), readFile(t, filepath.Join(raw.Root, rel)), project, environment)
			if err != nil {
				t.Fatal(err)
			}
			data, err := crypt.EncryptSecretFile(newKey, file)
			if err != nil {
				t.Fatal(err)
			}
			rawWrite(t, raw, rel, data)
			paths = append(paths, rel)
		}
		keyFile, err := crypt.EncryptKeyFile(newPassphrase, newKey)
		if err != nil {
			t.Fatal(err)
		}
		rawWrite(t, raw, store.KeyFileName, keyFile)
		rawPush(t, raw, "envs rotate", paths...)
		return newKey
	}

	t.Run("a read asks for the passphrase one time", func(t *testing.T) {
		w := newWorld(t)
		w.a.pipe(w.dir, "value", "set", "API_KEY")
		newKey := rotate(t, w)

		w.a.prompts = nil
		w.a.hidden = []string{newPassphrase}
		if r := w.a.ok(w.dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if len(w.a.prompts) != 1 || w.a.prompts[0] != "Passphrase: " {
			t.Errorf("prompts = %q, want one passphrase prompt", w.a.prompts)
		}
		if w.a.storeKey() != newKey {
			t.Error("the keychain does not hold the new store key")
		}
		w.a.pipe(w.dir, "", "list")
	})
	t.Run("a write in the retry sequence uses the new key", func(t *testing.T) {
		w := newWorld(t)
		w.a.pipe(w.dir, "value", "set", "API_KEY")
		newKey := rotate(t, w)

		w.a.hidden = []string{"second value", newPassphrase}
		w.a.ok(w.dir, "", "set", "SECOND")
		if w.a.storeKey() != newKey {
			t.Fatal("the keychain does not hold the new store key")
		}
		if got := w.a.values("myapp", "dev"); got["API_KEY"] != "value" || got["SECOND"] != "second value" {
			t.Error("the file has wrong values")
		}
	})
	t.Run("a new file does not use the old key", func(t *testing.T) {
		w := newWorld(t)
		w.a.pipe(w.dir, "value", "set", "API_KEY")
		newKey := rotate(t, w)

		w.a.hidden = []string{"new value", newPassphrase}
		w.a.ok(w.dir, "", "set", "API_KEY", "--env", "staging")
		if w.a.storeKey() != newKey {
			t.Fatal("the keychain does not hold the new store key")
		}
		if got := w.a.values("myapp", "staging")["API_KEY"]; got != "new value" {
			t.Error("the new file is not encrypted with the new key")
		}
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		w := newWorld(t)
		w.a.pipe(w.dir, "value", "set", "API_KEY")
		oldKey := w.a.storeKey()
		rotate(t, w)

		w.a.hidden = []string{passphrase}
		w.a.fails(w.dir, "", "passphrase is wrong", "list")
		if w.a.storeKey() != oldKey {
			t.Error("a failed unlock changed the keychain")
		}
	})
	t.Run("stdin is not a terminal", func(t *testing.T) {
		w := newWorld(t)
		w.a.pipe(w.dir, "value", "set", "API_KEY")
		rotate(t, w)
		w.a.pipeFails(w.dir, "", "stdin is not a terminal", "list")
	})
}

func TestPassphraseChangeOnAnotherDevice(t *testing.T) {
	w := newWorld(t)
	w.a.pipe(w.dir, "value", "set", "API_KEY")
	_, oldHash, _ := strings.Cut(w.a.keychain, ":")

	// "envs passwd" on another device encrypts only key.age again.
	keyFile, err := crypt.EncryptKeyFile("a new and longer passphrase", w.a.storeKey())
	if err != nil {
		t.Fatal(err)
	}
	rawCommit(t, w.remote, store.KeyFileName, keyFile)

	if r := w.a.pipe(w.dir, "", "list"); r.stdout != "API_KEY\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
	_, newHash, _ := strings.Cut(w.a.keychain, ":")
	if newHash == oldHash || newHash != crypt.Hash(keyFile) {
		t.Error("the cached hash was not updated to the new key.age")
	}
}

func TestNoKeychain(t *testing.T) {
	isolate(t)
	remote := bareRepo(t)
	d := newDevice(t)
	d.noKeychain = true
	d.hidden = []string{passphrase, passphrase}
	r := d.ok(d.home, "", "login", remote)
	if !strings.Contains(r.stderr, "warning: cannot save the store key in the OS keychain") {
		t.Errorf("stderr = %q, want a keychain warning", r.stderr)
	}
	dir := projectDir(t, "myapp")
	d.ok(dir, "", "init")

	t.Run("each command asks for the passphrase", func(t *testing.T) {
		d.hidden = []string{"value", passphrase}
		d.ok(dir, "", "set", "API_KEY")
		d.prompts = nil
		d.hidden = []string{passphrase}
		if r := d.ok(dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if len(d.prompts) != 1 || d.prompts[0] != "Passphrase: " {
			t.Errorf("prompts = %q", d.prompts)
		}
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		d.hidden = []string{"wrong horse battery staple"}
		d.fails(dir, "", "passphrase is wrong", "list")
	})
	t.Run("stdin is not a terminal", func(t *testing.T) {
		d.pipeFails(dir, "", "the store key is not in the OS keychain, and stdin is not a terminal", "list")
	})
	t.Run("no file in the home folder holds the key or the passphrase", func(t *testing.T) {
		key, err := crypt.DecryptKeyFile(passphrase, readFile(t, filepath.Join(d.storeDir(), "key.age")))
		if err != nil {
			t.Fatal(err)
		}
		assertNotOnDisk(t, d.home, key, passphrase)
	})
}
