package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lminii/envs/internal/crypt"
)

const nextPassphrase = "a new and longer passphrase"

func TestLogout(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	d.pipe(dir, "value", "set", "API_KEY")

	t.Run("with an argument", func(t *testing.T) {
		d.fails(dir, "", "envs logout takes no arguments", "logout", "now")
		if _, err := os.Stat(d.storeDir()); err != nil {
			t.Error("a failed logout removed the store")
		}
	})
	t.Run("removes the key and the clone", func(t *testing.T) {
		r := d.ok(dir, "", "logout")
		if !strings.Contains(r.stdout, "Logged out") {
			t.Errorf("stdout = %q", r.stdout)
		}
		if _, err := os.Stat(d.storeDir()); err == nil {
			t.Error("the clone is still on the device")
		}
		if d.keychain != "" {
			t.Error("the store key is still in the keychain")
		}
		if _, err := os.Stat(filepath.Join(d.home, ".envs", "trusted.json")); err != nil {
			t.Error("logout removed the trusted folder list")
		}
	})
	t.Run("commands point to login", func(t *testing.T) {
		d.fails(dir, "", "this device has no store. Run \"envs login <repo-url>\"", "list")
	})
	t.Run("a second logout succeeds", func(t *testing.T) {
		d.ok(dir, "", "logout")
	})
	t.Run("login after logout", func(t *testing.T) {
		d.login(w.remote, false)
		if r := d.pipe(dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("a device with no keychain", func(t *testing.T) {
		b := newDevice(t)
		b.noKeychain = true
		b.login(w.remote, false)
		r := b.ok(b.home, "", "logout")
		if !strings.Contains(r.stderr, "warning: cannot remove the store key from the OS keychain") {
			t.Errorf("stderr = %q", r.stderr)
		}
		if _, err := os.Stat(b.storeDir()); err == nil {
			t.Error("the clone is still on the device")
		}
	})
}

func TestPasswd(t *testing.T) {
	w := newWorld(t)
	a, dir := w.a, w.dir
	a.pipe(dir, "value", "set", "API_KEY")
	b, dirB := w.second(t)
	secret := remoteFile(t, w, "myapp/dev.age")
	storeKey := a.storeKey()
	head := git(t, w.remote, "rev-parse", "main")

	errorCases := []struct {
		name   string
		hidden []string
		want   string
		args   []string
	}{
		{"wrong current passphrase", []string{"wrong horse battery staple"}, "the passphrase is wrong", []string{"passwd"}},
		{"short new passphrase", []string{passphrase, "only15character"}, "the passphrase has fewer than 16 characters. Run \"envs passwd\" again", []string{"passwd"}},
		{"new passphrases are not equal", []string{passphrase, nextPassphrase, nextPassphrase + "x"}, "the two passphrases are not equal. Run \"envs passwd\" again", []string{"passwd"}},
		{"with an argument", nil, "envs passwd takes no arguments", []string{"passwd", nextPassphrase}},
	}
	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			a.hidden = c.hidden
			a.fails(dir, "", c.want, c.args...)
		})
	}
	t.Run("stdin is not a terminal", func(t *testing.T) {
		a.pipeFails(dir, passphrase+"\n", "stdin is not a terminal", "passwd")
	})
	t.Run("failed commands change nothing", func(t *testing.T) {
		if git(t, w.remote, "rev-parse", "main") != head {
			t.Error("a failed passwd pushed a commit")
		}
		if out := git(t, a.storeDir(), "status", "--porcelain"); out != "" {
			t.Errorf("the clone is not clean: %q", out)
		}
	})

	a.prompts = nil
	a.hidden = []string{passphrase, nextPassphrase, nextPassphrase}
	r := a.ok(dir, "", "passwd")

	t.Run("prompts and output", func(t *testing.T) {
		want := []string{"Current passphrase: ", "New passphrase (16 characters or more): ", "Repeat the passphrase: "}
		if strings.Join(a.prompts, "|") != strings.Join(want, "|") {
			t.Errorf("prompts = %q", a.prompts)
		}
		if !strings.Contains(r.stdout, "Changed the passphrase") || !strings.Contains(r.stdout, "envs rotate") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("one commit that changes key.age only", func(t *testing.T) {
		if got := git(t, w.remote, "show", "--name-only", "--format=%s", "main"); got != "envs passwd\n\nkey.age" {
			t.Errorf("commit = %q", got)
		}
		if !bytes.Equal(remoteFile(t, w, "myapp/dev.age"), secret) {
			t.Error("passwd changed a secret file")
		}
	})
	t.Run("the old passphrase fails and the new one works", func(t *testing.T) {
		keyFile := remoteFile(t, w, "key.age")
		if _, err := crypt.DecryptKeyFile(passphrase, keyFile); !errors.Is(err, crypt.ErrWrongKey) {
			t.Errorf("old passphrase: error = %v, want ErrWrongKey", err)
		}
		if key, err := crypt.DecryptKeyFile(nextPassphrase, keyFile); err != nil || key != storeKey {
			t.Errorf("new passphrase does not give the same store key: %v", err)
		}
		d := newDevice(t)
		d.hidden = []string{passphrase}
		d.fails(d.home, "", "the passphrase is wrong", "login", w.remote)
		d.hidden = []string{nextPassphrase}
		d.ok(d.home, "", "login", w.remote)
	})
	t.Run("this device continues with no prompt", func(t *testing.T) {
		if r := a.pipe(dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if _, hash, _ := strings.Cut(a.keychain, ":"); hash != crypt.Hash(remoteFile(t, w, "key.age")) {
			t.Error("the cached hash is not the hash of the new key.age")
		}
	})
	t.Run("another device continues with no prompt", func(t *testing.T) {
		if r := b.pipe(dirB, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		b.pipe(dirB, "from-b", "set", "SECOND")
	})
}

func TestRotate(t *testing.T) {
	w := newWorld(t)
	a, dir := w.a, w.dir
	a.pipe(dir, "dev-value", "set", "API_KEY")
	a.pipe(dir, "prod-value", "set", "API_KEY", "--env", "prod")
	a.pipe(dir, "other-value", "set", "TOKEN", "--project", "other")
	b, dirB := w.second(t)
	oldKey := a.storeKey()
	head := git(t, w.remote, "rev-parse", "main")

	t.Run("wrong passphrase", func(t *testing.T) {
		a.hidden = []string{"wrong horse battery staple"}
		a.fails(dir, "", "the passphrase is wrong", "rotate")
	})
	t.Run("stdin is not a terminal", func(t *testing.T) {
		a.pipeFails(dir, passphrase+"\n", "stdin is not a terminal", "rotate")
	})
	t.Run("with an argument", func(t *testing.T) {
		a.fails(dir, "", "envs rotate takes no arguments", "rotate", "now")
	})
	t.Run("failed commands change nothing", func(t *testing.T) {
		if git(t, w.remote, "rev-parse", "main") != head || a.storeKey() != oldKey {
			t.Error("a failed rotate changed the store")
		}
	})

	a.prompts = nil
	a.hidden = []string{passphrase}
	r := a.ok(dir, "", "rotate")

	t.Run("prompts and output", func(t *testing.T) {
		if len(a.prompts) != 1 || a.prompts[0] != "Passphrase: " {
			t.Errorf("prompts = %q", a.prompts)
		}
		if !strings.Contains(r.stdout, "encrypted 3 files again") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("one commit with key.age and all files", func(t *testing.T) {
		got := git(t, w.remote, "show", "--name-only", "--format=%s", "main")
		if want := "envs rotate\n\nkey.age\nmyapp/dev.age\nmyapp/prod.age\nother/dev.age"; got != want {
			t.Errorf("commit = %q, want %q", got, want)
		}
		if parent := git(t, w.remote, "rev-parse", "main~1"); parent != head {
			t.Error("rotate made more than one commit")
		}
	})
	t.Run("the store has a new key", func(t *testing.T) {
		newKey := a.storeKey()
		if newKey == oldKey || !crypt.ValidStoreKey(newKey) {
			t.Fatal("the keychain does not hold a new store key")
		}
		if key, err := crypt.DecryptKeyFile(passphrase, remoteFile(t, w, "key.age")); err != nil || key != newKey {
			t.Errorf("key.age does not hold the new key: %v", err)
		}
		for _, f := range []struct{ project, environment, key, value string }{
			{"myapp", "dev", "API_KEY", "dev-value"},
			{"myapp", "prod", "API_KEY", "prod-value"},
			{"other", "dev", "TOKEN", "other-value"},
		} {
			data := remoteFile(t, w, f.project+"/"+f.environment+".age")
			if _, err := crypt.DecryptSecretFile(oldKey, data, f.project, f.environment); !errors.Is(err, crypt.ErrWrongKey) {
				t.Errorf("%s/%s: the old key gives %v, want ErrWrongKey", f.project, f.environment, err)
			}
			file, err := crypt.DecryptSecretFile(newKey, data, f.project, f.environment)
			if err != nil || len(file.Values) != 1 || file.Values[f.key] != f.value {
				t.Errorf("%s/%s: the values changed: %v", f.project, f.environment, err)
			}
		}
	})
	t.Run("this device continues with no prompt", func(t *testing.T) {
		if r := a.pipe(dir, "", "list"); r.stdout != "API_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		a.pipe(dir, "new", "set", "AFTER")
	})
	t.Run("another device asks for the passphrase one time", func(t *testing.T) {
		b.prompts = nil
		b.hidden = []string{passphrase}
		if r := b.ok(dirB, "", "list"); r.stdout != "AFTER\nAPI_KEY\n" {
			t.Errorf("stdout = %q", r.stdout)
		}
		if len(b.prompts) != 1 || b.prompts[0] != "Passphrase: " {
			t.Errorf("prompts = %q, want one passphrase prompt", b.prompts)
		}
		if b.storeKey() != a.storeKey() {
			t.Error("the other device does not have the new key")
		}
		b.pipe(dirB, "from-b", "set", "SECOND")
		if got := childValue(t, a, dir, "SECOND"); got != "from-b" {
			t.Errorf("child value on the first device = %q", got)
		}
	})
	t.Run("a new device logs in", func(t *testing.T) {
		d := newDevice(t)
		d.login(w.remote, false)
		if d.storeKey() != a.storeKey() {
			t.Error("the new device does not have the new key")
		}
	})
}

func TestRotateStopsOnDamagedFile(t *testing.T) {
	w := newWorld(t)
	a, dir := w.a, w.dir
	a.pipe(dir, "dev-value", "set", "API_KEY")
	a.pipe(dir, "prod-value", "set", "API_KEY", "--env", "prod")

	otherKey, err := crypt.NewStoreKey()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := crypt.EncryptSecretFile(otherKey, crypt.NewSecretFile("myapp", "prod"))
	if err != nil {
		t.Fatal(err)
	}
	rawCommit(t, w.remote, "myapp/prod.age", forged)
	head := git(t, w.remote, "rev-parse", "main")
	oldKey := a.storeKey()

	a.hidden = []string{passphrase}
	a.fails(dir, "", "the store key cannot decrypt myapp/prod.age. "+outsideEnvs, "rotate")

	if git(t, w.remote, "rev-parse", "main") != head {
		t.Error("the rotation pushed a commit")
	}
	if out := git(t, a.storeDir(), "status", "--porcelain"); out != "" {
		t.Errorf("the clone is not clean: %q", out)
	}
	if a.storeKey() != oldKey {
		t.Error("the keychain has a new key")
	}
	if got := a.values("myapp", "dev")["API_KEY"]; got != "dev-value" {
		t.Error("the old key does not decrypt the other file")
	}
}

func TestLog(t *testing.T) {
	w := newWorld(t)
	d, dir := w.a, w.dir
	d.pipe(dir, "value", "set", "API_KEY")
	d.pipe(dir, "value", "set", "DB_URL", "--env", "prod")
	d.pipe(dir, "value", "set", "TOKEN", "--project", "other")
	d.pipe(dir, "", "rm", "API_KEY")

	line := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}  (.*)$`)
	subjects := func(t *testing.T, r result) string {
		t.Helper()
		var out []string
		for _, l := range strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n") {
			m := line.FindStringSubmatch(l)
			if m == nil {
				t.Fatalf("line %q is not a date and a subject", l)
			}
			out = append(out, m[1])
		}
		return strings.Join(out, "\n")
	}

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"all environments of the project", []string{"log"}, "envs rm myapp/dev API_KEY\nenvs set myapp/prod DB_URL\nenvs set myapp/dev API_KEY"},
		{"one environment", []string{"log", "--env", "prod"}, "envs set myapp/prod DB_URL"},
		{"the default environment by name", []string{"log", "--env", "dev"}, "envs rm myapp/dev API_KEY\nenvs set myapp/dev API_KEY"},
		{"another project", []string{"log", "--project", "other"}, "envs set other/dev TOKEN"},
		{"offline", []string{"log", "--offline", "--env", "prod"}, "envs set myapp/prod DB_URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := d.pipe(dir, "", c.args...)
			if got := subjects(t, r); got != c.want {
				t.Errorf("subjects = %q, want %q", got, c.want)
			}
			if r.stderr != "" {
				t.Errorf("stderr = %q", r.stderr)
			}
		})
	}

	errorCases := []struct {
		name string
		want string
		args []string
	}{
		{"project with no history", "the store has no history for missing. Run \"envs set <KEY>\"", []string{"log", "--project", "missing"}},
		{"environment with no history", "the store has no history for myapp/staging", []string{"log", "--env", "staging"}},
		{"with an argument", "envs log takes no arguments", []string{"log", "API_KEY"}},
	}
	for _, c := range errorCases {
		t.Run(c.name, func(t *testing.T) {
			d.pipeFails(dir, "", c.want, c.args...)
		})
	}

	t.Run("control characters in a commit subject are not printed", func(t *testing.T) {
		raw := rawClone(t, w.remote)
		rawWrite(t, raw, "myapp/note", []byte("x"))
		rawPush(t, raw, "evil\x1b[2J\x07subject", "myapp/note")
		r := d.pipe(dir, "", "log")
		if strings.ContainsAny(r.stdout, "\x1b\x07") {
			t.Errorf("stdout has control characters: %q", r.stdout)
		}
		if !strings.Contains(r.stdout, "  evil?[2J?subject\n") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
}
