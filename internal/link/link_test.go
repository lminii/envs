package link

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	dir := filepath.Join(parts...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFind(t *testing.T) {
	root := t.TempDir()
	// The temporary folder can sit below a repository or a link file.
	mkdir(t, root, ".git")

	linked := mkdir(t, root, "linked")
	if err := Write(linked, "myapp"); err != nil {
		t.Fatal(err)
	}
	sub := mkdir(t, linked, "src", "deep")
	nestedDir := mkdir(t, linked, "tmp", "clone")
	mkdir(t, nestedDir, ".git")
	nestedSub := mkdir(t, nestedDir, "pkg")
	nestedFile := mkdir(t, linked, "tmp", "worktree")
	write(t, filepath.Join(nestedFile, ".git"), "gitdir: elsewhere\n")
	both := mkdir(t, linked, "tmp", "both")
	mkdir(t, both, ".git")
	if err := Write(both, "other"); err != nil {
		t.Fatal(err)
	}
	unlinked := mkdir(t, root, "unlinked", "src")

	cases := []struct {
		name        string
		dir         string
		wantFolder  string
		wantProject string
		wantErr     error
	}{
		{"same folder", linked, linked, "myapp", nil},
		{"subfolder", sub, linked, "myapp", nil},
		{"nested repository", nestedDir, "", "", ErrNotFound},
		{"below a nested repository", nestedSub, "", "", ErrNotFound},
		{"nested .git file", nestedFile, "", "", ErrNotFound},
		{"link file and .git in one folder", both, both, "other", nil},
		{"no link file", unlinked, "", "", ErrNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			folder, project, err := Find(c.dir)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("error = %v, want %v", err, c.wantErr)
			}
			if folder != c.wantFolder || project != c.wantProject {
				t.Fatalf("Find = %q, %q, want %q, %q", folder, project, c.wantFolder, c.wantProject)
			}
		})
	}
}

func TestFindInvalidLinkFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"not JSON", "myapp"},
		{"unknown field", `{"project":"myapp","env":"prod"}`},
		{"path in name", `{"project":"../other"}`},
		{"uppercase name", `{"project":"MyApp"}`},
		{"missing name", `{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, FileName), c.content)
			_, _, err := Find(dir)
			if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "invalid link file") {
				t.Fatalf("error = %v, want an invalid link file error", err)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, "myapp"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"project\":\"myapp\"}\n" {
		t.Fatalf("link file = %q", data)
	}
}

func TestTrusted(t *testing.T) {
	envsDir := filepath.Join(t.TempDir(), ".envs")
	folder, err := Canonical(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := Canonical(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	check := func(folder, project string, want bool) {
		t.Helper()
		got, err := IsTrusted(envsDir, folder, project)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("IsTrusted(%q, %q) = %v, want %v", folder, project, got, want)
		}
	}

	check(folder, "myapp", false)
	if err := Trust(envsDir, folder, "myapp"); err != nil {
		t.Fatal(err)
	}
	check(folder, "myapp", true)
	check(folder, "other", false)
	check(other, "myapp", false)
	check(filepath.Join(folder, "sub"), "myapp", false)
	check(strings.ToUpper(folder), "myapp", runtime.GOOS == "windows" || strings.ToUpper(folder) == folder)

	if err := Trust(envsDir, other, "second"); err != nil {
		t.Fatal(err)
	}
	check(folder, "myapp", true)
	check(other, "second", true)

	if err := Trust(envsDir, folder, "renamed"); err != nil {
		t.Fatal(err)
	}
	check(folder, "renamed", true)
	check(folder, "myapp", false)

	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{envsDir: 0o700, filepath.Join(envsDir, trustedFileName): 0o600} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != want {
				t.Errorf("%s has mode %o, want %o", path, info.Mode().Perm(), want)
			}
		}
	}
}

func TestCanonicalResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := mkdir(t, dir, "target")
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}
	a, err := Canonical(alias)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Canonical(target)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("Canonical(alias) = %q, Canonical(target) = %q", a, b)
	}
}

func TestTrustedFileErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantMsg string
	}{
		{"not JSON", "{", "not valid JSON"},
		{"version 2", `{"version":2,"folders":[]}`, "Update envs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			envsDir := t.TempDir()
			write(t, filepath.Join(envsDir, trustedFileName), c.content)
			_, err := IsTrusted(envsDir, envsDir, "myapp")
			if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("error = %v, want it to contain %q", err, c.wantMsg)
			}
		})
	}
}
