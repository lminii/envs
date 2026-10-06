// Package store runs git on the local clone of the store repository (PRD 8.1 and 8.7).
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lminii/envs/internal/names"
)

const (
	KeyFileName        = "key.age"
	AttributesFileName = ".gitattributes"
	// Attributes stops core.autocrlf from changing ciphertext.
	Attributes = "*.age binary\n"

	remote = "origin"
	branch = "main"

	readFetchTimeout  = 5 * time.Second
	writeFetchTimeout = 30 * time.Second
	pushTimeout       = 2 * time.Minute
	localTimeout      = 30 * time.Second
)

var (
	// ErrFetch means the remote was not reachable.
	ErrFetch = errors.New("fetch failed")
	// ErrNonFastForward means the remote history is not a continuation of the local history.
	ErrNonFastForward = errors.New("the remote history changed")
	// ErrPush means the remote did not accept the push.
	ErrPush = errors.New("push failed")
	// ErrNoStore means no local clone exists.
	ErrNoStore = errors.New("no store")
)

// Git hooks and some tools set these, and they redirect git to another repository.
var removedEnv = []string{
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_INDEX_FILE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_COMMON_DIR",
	"GIT_NAMESPACE",
	"GIT_PREFIX",
}

var commitConfig = []string{
	"-c", "commit.gpgsign=false",
	"-c", "user.name=envs",
	"-c", "user.email=envs@localhost",
}

var remoteHelper = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+.-]*::`)

type Store struct {
	Root string
}

// ValidateURL checks a repository URL before git gets it.
func ValidateURL(repoURL string) error {
	switch {
	case repoURL == "":
		return errors.New("the repository URL is empty. Run \"envs login <repo-url>\"")
	case strings.HasPrefix(repoURL, "-"):
		return errors.New("the repository URL starts with \"-\". Use an https URL, an ssh URL, or a local path")
	case strings.ContainsFunc(repoURL, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return errors.New("the repository URL contains a control character. Use an https URL, an ssh URL, or a local path")
	case remoteHelper.MatchString(repoURL):
		return errors.New("the repository URL uses remote helper syntax (\"<name>::\"). Use an https URL, an ssh URL, or a local path")
	}
	scheme, _, hasScheme := strings.Cut(repoURL, "://")
	if !hasScheme {
		return nil
	}
	switch strings.ToLower(scheme) {
	case "ssh":
		return nil
	case "https":
		u, err := url.Parse(repoURL)
		if err != nil {
			return errors.New("the repository URL is not a valid https URL. Use the form https://host/owner/repo.git")
		}
		if u.User != nil {
			return errors.New("the repository URL contains a user name or token, and git would store it in plaintext. Remove it and use the git credential helper")
		}
		return nil
	}
	return fmt.Errorf("the repository URL uses the scheme %q. Use an https URL, an ssh URL, or a local path", scheme)
}

// Open returns the store at root. It returns ErrNoStore when root is not a clone.
func Open(root string) (*Store, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil, ErrNoStore
	}
	return &Store{Root: root}, nil
}

// Clone clones repoURL to root. empty is true when the remote has no commits.
func Clone(ctx context.Context, repoURL, root string) (s *Store, empty bool, err error) {
	if err := ValidateURL(repoURL); err != nil {
		return nil, false, err
	}
	if _, err := runGit(ctx, "", nil, "clone", "--quiet", "-c", "init.defaultBranch="+branch, "--", repoURL, root); err != nil {
		return nil, false, err
	}
	s = &Store{Root: root}
	refs, err := s.local(ctx, "for-each-ref", "--count=1", "refs/remotes/"+remote)
	if err != nil {
		return nil, false, err
	}
	if refs == "" {
		if _, err := s.local(ctx, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
			return nil, false, err
		}
		return s, true, nil
	}
	if _, err := s.local(ctx, "rev-parse", "--verify", "--quiet", "refs/remotes/"+remote+"/"+branch); err != nil {
		return nil, false, fmt.Errorf("the repository has no branch %q. Use an empty repository or an envs store", branch)
	}
	if _, err := s.local(ctx, "checkout", "--quiet", "-B", branch, "refs/remotes/"+remote+"/"+branch); err != nil {
		return nil, false, err
	}
	return s, false, nil
}

// Sync fetches the remote and fast-forwards the local clone. With quiet set,
// it is the sync before a read: a 5 s fetch with all credential prompts off.
func (s *Store) Sync(ctx context.Context, quiet bool) error {
	timeout := writeFetchTimeout
	var env []string
	if quiet {
		timeout = readFetchTimeout
		env = s.noPromptEnv(ctx)
	}
	if err := s.fetch(ctx, timeout, env); err != nil {
		return err
	}
	// The merge has no timeout. A kill during a merge can leave the clone in a merging state.
	if _, err := runGit(context.WithoutCancel(ctx), s.Root, nil, "merge", "--ff-only", "--quiet", remote+"/"+branch); err != nil {
		return ErrNonFastForward
	}
	return nil
}

func (s *Store) fetch(ctx context.Context, timeout time.Duration, env []string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := runGit(ctx, s.Root, env, "fetch", "--quiet", remote, branch); err != nil {
		return fmt.Errorf("%w: %v", ErrFetch, err)
	}
	return nil
}

func (s *Store) noPromptEnv(ctx context.Context) []string {
	env := []string{"GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never"}
	if _, set := os.LookupEnv("GIT_SSH_COMMAND"); set {
		return env
	}
	remoteURL, err := s.RemoteURL(ctx)
	if err != nil || !isSSH(remoteURL) {
		return env
	}
	if _, err := s.local(ctx, "config", "--get", "core.sshCommand"); err == nil {
		return env
	}
	return append(env, "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
}

// RemoteURL returns the URL that the store was cloned from.
func (s *Store) RemoteURL(ctx context.Context) (string, error) {
	return s.local(ctx, "config", "--get", "remote."+remote+".url")
}

func isSSH(remoteURL string) bool {
	if scheme, _, ok := strings.Cut(remoteURL, "://"); ok {
		return strings.EqualFold(scheme, "ssh")
	}
	// scp form: [user@]host:path. A one-letter host is a Windows drive.
	host, _, ok := strings.Cut(remoteURL, ":")
	return ok && len(host) > 1 && !strings.ContainsAny(host, `/\`)
}

// Commit stages the paths, which are relative to the store root, and commits them.
func (s *Store) Commit(ctx context.Context, message string, paths ...string) error {
	if _, err := s.local(ctx, append([]string{"add", "--"}, paths...)...); err != nil {
		return err
	}
	args := append([]string{}, commitConfig...)
	args = append(args, "commit", "--quiet", "-m", message)
	_, err := s.local(ctx, args...)
	return err
}

func (s *Store) Push(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	if _, err := runGit(ctx, s.Root, nil, "push", "--quiet", remote, branch); err != nil {
		return fmt.Errorf("%w: %v", ErrPush, err)
	}
	return nil
}

// Discard removes local commits and changes that the remote does not have.
// The tool never keeps an unpushed commit.
func (s *Store) Discard(ctx context.Context) error {
	fetchErr := s.fetch(ctx, writeFetchTimeout, nil)
	if err := s.resetTo(ctx, remote+"/"+branch); err != nil {
		return err
	}
	return fetchErr
}

// Restore removes changes in the clone that are not committed.
func (s *Store) Restore(ctx context.Context) error {
	return s.resetTo(ctx, "HEAD")
}

func (s *Store) resetTo(ctx context.Context, commit string) error {
	if _, err := s.local(ctx, "reset", "--hard", "--quiet", commit); err != nil {
		return err
	}
	_, err := s.local(ctx, "clean", "-fd", "--quiet")
	return err
}

// Log returns one line for each commit that changed path, newest first. The
// line is the local commit time, a tab, and the commit subject. path is
// relative to the store root.
func (s *Store) Log(ctx context.Context, path string) ([]string, error) {
	out, err := s.local(ctx, "log", "--format=%ad%x09%s", "--date=format-local:%Y-%m-%d %H:%M", "--", path)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// SecretPath returns the path of <project>/<environment>.age below the store root.
func (s *Store) SecretPath(project, environment string) (string, error) {
	if err := names.Project(project); err != nil {
		return "", err
	}
	if err := names.Environment(environment); err != nil {
		return "", err
	}
	path := filepath.Join(s.Root, project, environment+".age")
	rel, err := filepath.Rel(s.Root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("the path of %s/%s is outside the store", project, environment)
	}
	return path, nil
}

func (s *Store) KeyPath() string {
	return filepath.Join(s.Root, KeyFileName)
}

// Rel returns path relative to the store root, for Commit.
func (s *Store) Rel(path string) (string, error) {
	return filepath.Rel(s.Root, path)
}

func (s *Store) ProjectExists(project string) bool {
	if names.Project(project) != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(s.Root, project))
	return err == nil && info.IsDir()
}

// SecretFiles returns the paths of all secret files, relative to the store root.
func (s *Store) SecretFiles() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(s.Root, "*", "*.age"))
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(matches))
	for _, m := range matches {
		rel, err := filepath.Rel(s.Root, m)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			continue
		}
		files = append(files, rel)
	}
	return files, nil
}

func (s *Store) local(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, localTimeout)
	defer cancel()
	return runGit(ctx, s.Root, nil, args...)
}

func runGit(ctx context.Context, dir string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(cleanEnv(os.Environ()), extraEnv...)
	// On Windows a killed git can leave git-remote-https or ssh behind with
	// the output pipes open. WaitDelay stops the wait for them.
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return strings.TrimSpace(stdout.String()), nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "", errors.New("git is not on the PATH. Install git 2.30 or later")
	}
	verb := gitVerb(args)
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("git %s timed out", verb)
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return "", fmt.Errorf("git %s: %s", verb, msg)
	}
	return "", fmt.Errorf("git %s: %v", verb, err)
}

func gitVerb(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++
			continue
		}
		return args[i]
	}
	return ""
}

func cleanEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		removed := false
		for _, r := range removedEnv {
			if strings.EqualFold(name, r) {
				removed = true
				break
			}
		}
		if !removed {
			out = append(out, kv)
		}
	}
	return out
}
