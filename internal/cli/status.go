package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/keycache"
	"github.com/lminii/envs/internal/link"
	"github.com/lminii/envs/internal/names"
	"github.com/lminii/envs/internal/store"
)

// status prints the state of this device and folder, one line for each part
// that "envs run" needs. It never prompts, so it works without a terminal, and
// it prints key counts but no names or values.
func (a *App) status(ctx context.Context, args []string) error {
	opts, positional, err := a.parse("status", args, true, true)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return errors.New("envs status takes no arguments. Run \"envs status\"")
	}
	line := func(label, format string, args ...any) {
		fmt.Fprintf(a.Stdout, "%-11s"+format+"\n", append([]any{label}, args...)...)
	}

	s, err := store.Open(a.storeDir())
	if errors.Is(err, store.ErrNoStore) {
		line("Store", "none on this device. Run \"envs login <repo-url>\"")
		return nil
	}
	if err != nil {
		return err
	}
	line("Store", "%s", s.Root)
	if remoteURL, err := s.RemoteURL(ctx); err == nil {
		line("Remote", "%s", remoteURL)
	}
	if opts.offline {
		line("Sync", "skipped (--offline)")
	} else {
		a.statusSync(ctx, line, s)
	}
	key, _, cached := keycache.Get()
	if cached {
		line("Key", "in the OS keychain")
	} else {
		line("Key", "not in the OS keychain. The next command asks for the passphrase")
	}

	project := opts.project
	if project != "" {
		if err := names.Project(project); err != nil {
			return err
		}
		line("Project", "%s (from --project)", project)
	} else {
		folder, found, err := link.Find(a.Dir)
		switch {
		case errors.Is(err, link.ErrNotFound):
			line("Project", "none. Run \"envs init\" in the project folder")
			if rule := store.IgnoreRule(ctx, a.Dir, link.FileName); rule != "" {
				line("Link file", "ignored by git (%s). %s", rule, unignoreHint)
			}
			return nil
		case err != nil:
			return err
		}
		project = found
		line("Project", "%s (from %s)", project, filepath.Join(folder, link.FileName))
		a.statusFolder(ctx, line, folder, project)
	}
	if !cached {
		return nil
	}

	t := target{project: project, environment: opts.environment}
	path, err := s.SecretPath(t.project, t.environment)
	if err != nil {
		return err
	}
	data, err := crypt.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		line("Values", "none in %s. Run \"envs set <KEY>\" to add one", t)
		return nil
	}
	if err == nil {
		var file *crypt.SecretFile
		if file, err = crypt.DecryptSecretFile(key, data, t.project, t.environment); err == nil {
			line("Values", "%d in %s", len(file.Values), t)
			return nil
		}
	}
	line("Values", "cannot read %s.age with the cached key. Run \"envs list\" for details", t)
	return nil
}

func (a *App) statusSync(ctx context.Context, line func(string, string, ...any), s *store.Store) {
	switch err := s.Sync(ctx, true); {
	case errors.Is(err, store.ErrNonFastForward):
		line("Sync", "the remote history changed outside envs. Examine the remote repository")
	case err != nil:
		line("Sync", "failed (%v). Commands use the local copy", err)
	default:
		line("Sync", "up to date")
	}
}

// statusFolder prints whether the linked folder is trusted and whether its
// link file reaches other devices through git.
func (a *App) statusFolder(ctx context.Context, line func(string, string, ...any), folder, project string) {
	canonical, err := link.Canonical(folder)
	if err == nil {
		if trusted, err := link.IsTrusted(a.envsDir(), canonical, project); err == nil && trusted {
			line("Folder", "trusted")
		} else if err == nil {
			line("Folder", "not trusted on this device. The next command asks you to confirm it")
		}
	}
	switch {
	case !store.InWorkTree(ctx, folder):
		// Not a git repository, so there is nothing to commit.
	case store.IsTracked(ctx, folder, link.FileName):
		line("Link file", "committed")
	default:
		if rule := store.IgnoreRule(ctx, folder, link.FileName); rule != "" {
			line("Link file", "ignored by git (%s). %s", rule, unignoreHint)
		} else {
			line("Link file", "not committed. Commit %s so your other devices get it", link.FileName)
		}
	}
}
