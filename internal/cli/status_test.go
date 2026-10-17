package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gitProject returns a new git repository with the given .gitignore, as a
// project created from a template.
func gitProject(t *testing.T, gitignore string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "myapp")
	git(t, "", "init", "--quiet", "--", dir)
	if gitignore != "" {
		if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignore), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestIgnoredLinkFile(t *testing.T) {
	w := newWorld(t)
	b := newDevice(t)
	b.login(w.remote, false)

	t.Run("init warns about a .env* rule", func(t *testing.T) {
		dir := gitProject(t, "node_modules\n.env*\n")
		r := w.a.ok(dir, "", "init", "other")
		for _, want := range []string{".gitignore:2:.env*", `"!.envs.json"`} {
			if !strings.Contains(r.stderr, want) {
				t.Errorf("stderr = %q, want it to contain %q", r.stderr, want)
			}
		}
	})
	t.Run("no warning after a negation", func(t *testing.T) {
		dir := gitProject(t, ".env*\n!.envs.json\n")
		if r := w.a.ok(dir, "", "init", "other"); r.stderr != "" {
			t.Errorf("stderr = %q, want no warning", r.stderr)
		}
	})
	t.Run("no warning outside a git repository", func(t *testing.T) {
		if r := w.a.ok(projectDir(t, "plain"), "", "init", "other"); r.stderr != "" {
			t.Errorf("stderr = %q, want no warning", r.stderr)
		}
	})
	t.Run("missing link file names the rule", func(t *testing.T) {
		dir := gitProject(t, ".env*\n")
		b.fails(dir, "", "git ignores .envs.json here because of the rule .gitignore:1:.env*", "list")
	})
	t.Run("missing link file without a rule", func(t *testing.T) {
		r := b.fails(gitProject(t, ""), "", "no link file found. Run \"envs init\"", "list")
		if strings.Contains(r.stderr, "git ignores") {
			t.Errorf("stderr = %q, want no rule", r.stderr)
		}
	})
}

func TestStatus(t *testing.T) {
	isolate(t)

	t.Run("no store", func(t *testing.T) {
		d := newDevice(t)
		r := d.pipe(projectDir(t, "myapp"), "", "status")
		if !strings.Contains(r.stdout, "envs login <repo-url>") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})

	w := newWorld(t)
	w.a.pipe(w.dir, "s3cret-value", "set", "API_KEY")

	t.Run("linked project", func(t *testing.T) {
		r := w.a.pipe(w.dir, "", "status")
		for _, want := range []string{"Sync       up to date", "Key        in the OS keychain", "Project    myapp", "Folder     trusted", "Values     1 in myapp/dev"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("stdout = %q, want it to contain %q", r.stdout, want)
			}
		}
		if strings.Contains(r.stdout+r.stderr, "API_KEY") || strings.Contains(r.stdout+r.stderr, "s3cret-value") {
			t.Error("status printed a key name or a value")
		}
	})
	t.Run("offline", func(t *testing.T) {
		r := w.a.pipe(w.dir, "", "status", "--offline")
		if !strings.Contains(r.stdout, "skipped (--offline)") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("untrusted folder does not prompt", func(t *testing.T) {
		b := newDevice(t)
		b.login(w.remote, false)
		dir := projectDir(t, "myapp")
		if err := os.WriteFile(filepath.Join(dir, ".envs.json"), []byte(`{"project":"myapp"}`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		r := b.pipe(dir, "", "status")
		if !strings.Contains(r.stdout, "not trusted on this device") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("no keychain entry", func(t *testing.T) {
		c := newDevice(t)
		c.login(w.remote, false)
		c.keychain = ""
		r := c.pipe(w.dir, "", "status")
		if !strings.Contains(r.stdout, "not in the OS keychain") || strings.Contains(r.stdout, "Values") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
	t.Run("link file in git", func(t *testing.T) {
		ignored := gitProject(t, ".env*\n")
		w.a.lines = []string{"yes"}
		w.a.ok(ignored, "", "init", "myapp")
		if r := w.a.pipe(ignored, "", "status"); !strings.Contains(r.stdout, "Link file  ignored by git (.gitignore:1:.env*)") {
			t.Errorf("stdout = %q", r.stdout)
		}

		dir := gitProject(t, "")
		w.a.lines = []string{"yes"}
		w.a.ok(dir, "", "init", "myapp")
		if r := w.a.pipe(dir, "", "status"); !strings.Contains(r.stdout, "Link file  not committed") {
			t.Errorf("stdout = %q", r.stdout)
		}
		git(t, dir, "add", "--", ".envs.json")
		if r := w.a.pipe(dir, "", "status"); !strings.Contains(r.stdout, "Link file  committed") {
			t.Errorf("stdout = %q", r.stdout)
		}
	})
}
