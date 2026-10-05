package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var ctx = context.Background()

func bareRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "remote.git")
	out, err := exec.Command("git", "init", "--quiet", "--bare", "--initial-branch=main", "--", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir
}

func clone(t *testing.T, remoteDir string) (*Store, bool) {
	t.Helper()
	s, empty, err := Clone(ctx, remoteDir, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	return s, empty
}

func commitFile(t *testing.T, s *Store, rel, content, message string) {
	t.Helper()
	path := filepath.Join(s.Root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, message, rel); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, s *Store, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.Root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// seeded returns a remote with one commit and a clone of it.
func seeded(t *testing.T) (remoteDir string, s *Store) {
	t.Helper()
	remoteDir = bareRepo(t)
	s, empty := clone(t, remoteDir)
	if !empty {
		t.Fatal("a new bare repository is not empty")
	}
	commitFile(t, s, AttributesFileName, Attributes, "envs login")
	if err := s.Push(ctx); err != nil {
		t.Fatal(err)
	}
	return remoteDir, s
}

func TestValidateURL(t *testing.T) {
	cases := []struct {
		url     string
		wantMsg string
	}{
		{"https://github.com/me/store.git", ""},
		{"ssh://git@github.com/me/store.git", ""},
		{"git@github.com:me/store.git", ""},
		{`C:\repos\store.git`, ""},
		{"/srv/git/store.git", ""},
		{"../store.git", ""},
		{"", "empty"},
		{"-oProxyCommand=calc", "starts with \"-\""},
		{"--upload-pack=calc", "starts with \"-\""},
		{"ext::sh -c calc", "remote helper"},
		{"fd::17", "remote helper"},
		{"https://me:token@github.com/me/store.git", "user name or token"},
		{"https://token@github.com/me/store.git", "user name or token"},
		{"HTTPS://token@github.com/me/store.git", "user name or token"},
		{"http://github.com/me/store.git", "scheme"},
		{"git://github.com/me/store.git", "scheme"},
		{"file:///srv/git/store.git", "scheme"},
		{"https://github.com/me/store.git\n-x", "control character"},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			err := ValidateURL(c.url)
			if c.wantMsg == "" {
				if err != nil {
					t.Fatalf("error = %v, want none", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("error = %v, want it to contain %q", err, c.wantMsg)
			}
		})
	}
}

func TestIsSSH(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"ssh://git@github.com/me/store.git", true},
		{"git@github.com:me/store.git", true},
		{"https://github.com/me/store.git", false},
		{`C:\repos\store.git`, false},
		{"C:/repos/store.git", false},
		{"/srv/git/store.git", false},
		{"./a:b", false},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			if got := isSSH(c.url); got != c.want {
				t.Fatalf("isSSH = %v, want %v", got, c.want)
			}
		})
	}
}

func TestCloneAndSync(t *testing.T) {
	remoteDir, a := seeded(t)

	b, empty := clone(t, remoteDir)
	if empty {
		t.Fatal("a store with one commit is empty")
	}
	// core.autocrlf of the user can change the line ending of this text file.
	if got := read(t, b, AttributesFileName); strings.TrimSpace(got) != strings.TrimSpace(Attributes) {
		t.Fatalf(".gitattributes = %q", got)
	}

	commitFile(t, a, "myapp/dev.age", "one", "envs set myapp/dev API_KEY")
	if err := a.Push(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	if got := read(t, b, "myapp/dev.age"); got != "one" {
		t.Fatalf("after sync the file is %q", got)
	}
	if !b.ProjectExists("myapp") || b.ProjectExists("other") {
		t.Fatal("ProjectExists is wrong")
	}
	files, err := b.SecretFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.ToSlash(files[0]) != "myapp/dev.age" {
		t.Fatalf("SecretFiles = %v", files)
	}
}

func TestCloneWithoutMainBranch(t *testing.T) {
	remoteDir := bareRepo(t)
	s, _ := clone(t, remoteDir)
	if _, err := s.local(ctx, "checkout", "--quiet", "-b", "other"); err != nil {
		t.Fatal(err)
	}
	commitFile(t, s, "readme", "x", "first")
	if _, err := s.local(ctx, "push", "--quiet", remote, "other"); err != nil {
		t.Fatal(err)
	}
	_, _, err := Clone(ctx, remoteDir, filepath.Join(t.TempDir(), "store"))
	if err == nil || !strings.Contains(err.Error(), "no branch \"main\"") {
		t.Fatalf("error = %v, want a missing branch error", err)
	}
}

func TestBinaryAttributeKeepsBytes(t *testing.T) {
	remoteDir, a := seeded(t)
	content := "age-encryption.org/v1\r\n-> scrypt x 10\n\x00\r\n"
	commitFile(t, a, "myapp/dev.age", content, "envs set myapp/dev K")
	if err := a.Push(ctx); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.autocrlf")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	b, _ := clone(t, remoteDir)
	if got := read(t, b, "myapp/dev.age"); got != content {
		t.Fatalf("core.autocrlf changed the file: %q", got)
	}
}

func TestSyncFailures(t *testing.T) {
	t.Run("remote not reachable", func(t *testing.T) {
		remoteDir, s := seeded(t)
		if err := os.RemoveAll(remoteDir); err != nil {
			t.Fatal(err)
		}
		if err := s.Sync(ctx, true); !errors.Is(err, ErrFetch) {
			t.Fatalf("error = %v, want ErrFetch", err)
		}
	})
	t.Run("remote history rewritten", func(t *testing.T) {
		remoteDir, a := seeded(t)
		commitFile(t, a, "myapp/dev.age", "one", "envs set myapp/dev K")
		if err := a.Push(ctx); err != nil {
			t.Fatal(err)
		}
		b, _ := clone(t, remoteDir)

		if _, err := a.local(ctx, "reset", "--hard", "--quiet", "HEAD~1"); err != nil {
			t.Fatal(err)
		}
		commitFile(t, a, "myapp/dev.age", "rewritten", "envs set myapp/dev K")
		if _, err := a.local(ctx, "push", "--quiet", "--force", remote, branch); err != nil {
			t.Fatal(err)
		}

		if err := b.Sync(ctx, true); !errors.Is(err, ErrNonFastForward) {
			t.Fatalf("error = %v, want ErrNonFastForward", err)
		}
		if got := read(t, b, "myapp/dev.age"); got != "one" {
			t.Fatalf("a failed sync changed the file to %q", got)
		}
	})
}

func TestPushRejectedAndDiscard(t *testing.T) {
	remoteDir, a := seeded(t)
	b, _ := clone(t, remoteDir)

	commitFile(t, a, "myapp/dev.age", "from a", "envs set myapp/dev K")
	if err := a.Push(ctx); err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, "myapp/dev.age", "from b", "envs set myapp/dev K")
	if err := b.Push(ctx); !errors.Is(err, ErrPush) {
		t.Fatalf("error = %v, want ErrPush", err)
	}
	if err := b.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	if got := read(t, b, "myapp/dev.age"); got != "from a" {
		t.Fatalf("after Discard the file is %q", got)
	}
	if err := b.Sync(ctx, false); err != nil {
		t.Fatal(err)
	}
}

func TestGitEnvironmentIsCleaned(t *testing.T) {
	remoteDir, a := seeded(t)
	elsewhere := t.TempDir()
	t.Setenv("GIT_DIR", filepath.Join(elsewhere, ".git"))
	t.Setenv("GIT_WORK_TREE", elsewhere)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(elsewhere, "index"))
	t.Setenv("GIT_PREFIX", "sub/")

	commitFile(t, a, "myapp/dev.age", "one", "envs set myapp/dev K")
	if err := a.Push(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ := clone(t, remoteDir)
	if got := read(t, b, "myapp/dev.age"); got != "one" {
		t.Fatalf("the clone has %q", got)
	}
	entries, err := os.ReadDir(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("git wrote to the folder from GIT_DIR: %v", entries)
	}
}

func TestCleanEnv(t *testing.T) {
	in := []string{"PATH=/bin", "GIT_DIR=/x"}
	for _, name := range removedEnv {
		in = append(in, name+"=value")
	}
	in = append(in, "git_dir=/lower", "GIT_SSH_COMMAND=ssh", "GIT_DIRECTORY=keep")
	got := strings.Join(cleanEnv(in), " ")
	if want := "PATH=/bin GIT_SSH_COMMAND=ssh GIT_DIRECTORY=keep"; got != want {
		t.Fatalf("cleanEnv = %q, want %q", got, want)
	}
}

func TestCommitIgnoresUserGitConfig(t *testing.T) {
	_, s := seeded(t)
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	t.Setenv("GIT_CONFIG_KEY_1", "gpg.program")
	t.Setenv("GIT_CONFIG_VALUE_1", "program-that-does-not-exist")
	commitFile(t, s, "myapp/dev.age", "one", "envs set myapp/dev K")
	author, err := s.local(ctx, "log", "-1", "--format=%an <%ae>")
	if err != nil {
		t.Fatal(err)
	}
	if author != "envs <envs@localhost>" {
		t.Fatalf("author = %q", author)
	}
}

func TestSecretPath(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	cases := []struct {
		name        string
		project     string
		environment string
		ok          bool
	}{
		{"valid", "myapp", "dev", true},
		{"parent in project", "..", "dev", false},
		{"separator in project", "a/b", "dev", false},
		{"backslash in environment", "myapp", `..\..\x`, false},
		{"empty environment", "myapp", "", false},
		{"absolute project", "/etc", "dev", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, err := s.SecretPath(c.project, c.environment)
			if (err == nil) != c.ok {
				t.Fatalf("error = %v, want ok = %v", err, c.ok)
			}
			if c.ok && path != filepath.Join(s.Root, "myapp", "dev.age") {
				t.Fatalf("path = %q", path)
			}
		})
	}
}

func TestOpen(t *testing.T) {
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrNoStore) {
		t.Fatalf("error = %v, want ErrNoStore", err)
	}
	_, s := seeded(t)
	if _, err := Open(s.Root); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreAndLog(t *testing.T) {
	_, s := seeded(t)
	commitFile(t, s, "myapp/dev.age", "one", "envs set myapp/dev K")
	commitFile(t, s, "other/dev.age", "one", "envs set other/dev K")

	if err := os.WriteFile(filepath.Join(s.Root, "myapp", "dev.age"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.Root, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root, "new", "dev.age"), []byte("untracked"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if got := read(t, s, "myapp/dev.age"); got != "one" {
		t.Errorf("after Restore the file is %q", got)
	}
	if status, err := s.local(ctx, "status", "--porcelain"); err != nil || status != "" {
		t.Errorf("after Restore the clone is not clean: %q, %v", status, err)
	}

	lines, err := s.Log(ctx, "myapp")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "\tenvs set myapp/dev K") {
		t.Errorf("Log = %q", lines)
	}
	if lines, err := s.Log(ctx, "missing"); err != nil || len(lines) != 0 {
		t.Errorf("Log of a missing path = %q, %v", lines, err)
	}
}
