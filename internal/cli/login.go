package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/keycache"
	"github.com/lminii/envs/internal/link"
	"github.com/lminii/envs/internal/names"
	"github.com/lminii/envs/internal/store"
)

func (a *App) login(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("envs login takes one repository URL. Run \"envs login <repo-url>\"")
	}
	repoURL := args[0]
	if err := store.ValidateURL(repoURL); err != nil {
		return err
	}
	if !a.IsTerminal() {
		return errors.New("stdin is not a terminal, and envs login reads the passphrase from a terminal. Run \"envs login <repo-url>\" in a terminal")
	}
	root := a.storeDir()
	if _, err := os.Lstat(root); err == nil {
		return fmt.Errorf("a store exists at %s. Run \"envs logout\" first", root)
	}
	if err := os.MkdirAll(a.envsDir(), 0o700); err != nil {
		return err
	}

	key, keyHash, err := a.cloneAndUnlock(ctx, repoURL, root)
	if err != nil {
		// A failed login leaves no clone, so the user can run it again.
		os.RemoveAll(root)
		return err
	}
	if err := keycache.Set(key, keyHash); err != nil {
		a.warn("cannot save the store key in the OS keychain (%v). envs asks for the passphrase on each command.", err)
	}
	fmt.Fprintf(a.Stdout, "Logged in. The store is at %s\n", root)
	return nil
}

func (a *App) cloneAndUnlock(ctx context.Context, repoURL, root string) (key, keyHash string, err error) {
	s, empty, err := store.Clone(ctx, repoURL, root)
	if err != nil {
		return "", "", err
	}
	if empty {
		return a.createStore(ctx, s)
	}

	data, err := crypt.ReadFile(s.KeyPath())
	if errors.Is(err, fs.ErrNotExist) {
		// A new key here would let a person who deleted key.age replace the store key.
		return "", "", errors.New("the repository has commits and no key.age. envs creates a store key only in an empty repository. If this is your store, it was changed outside envs: restore key.age from the git history of the repository. If not, run \"envs login\" with an empty repository")
	}
	if err != nil {
		return "", "", fmt.Errorf("cannot use key.age: %v. The store was changed outside envs. Restore key.age from the git history of the repository", err)
	}
	passphrase, err := a.ReadHidden("Passphrase: ")
	if err != nil {
		return "", "", err
	}
	key, err = crypt.DecryptKeyFile(passphrase, data)
	switch {
	case errors.Is(err, crypt.ErrWrongKey):
		return "", "", errors.New("the passphrase is wrong. Run \"envs login\" again")
	case err != nil:
		return "", "", fmt.Errorf("cannot use key.age: %v. The store was changed outside envs. Restore key.age from the git history of the repository", err)
	}
	return key, crypt.Hash(data), nil
}

func (a *App) createStore(ctx context.Context, s *store.Store) (key, keyHash string, err error) {
	passphrase, err := a.newPassphrase("The repository is empty. ", "login")
	if err != nil {
		return "", "", err
	}

	key, err = crypt.NewStoreKey()
	if err != nil {
		return "", "", err
	}
	data, err := crypt.EncryptKeyFile(passphrase, key)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(s.Root, store.AttributesFileName), []byte(store.Attributes), 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(s.KeyPath(), data, 0o644); err != nil {
		return "", "", err
	}
	if err := s.Commit(ctx, "envs login", store.AttributesFileName, store.KeyFileName); err != nil {
		return "", "", err
	}
	if err := s.Push(ctx); err != nil {
		// No retry with this key. If another device created the store at the
		// same time, its key is the store key.
		return "", "", fmt.Errorf("%v. The local clone and the new store key were deleted. Run \"envs login\" again", err)
	}
	return key, crypt.Hash(data), nil
}

// newPassphrase asks for a new passphrase two times.
func (a *App) newPassphrase(lead, command string) (string, error) {
	passphrase, err := a.ReadHidden(fmt.Sprintf("%sNew passphrase (%d characters or more): ", lead, crypt.MinPassphraseLength))
	if err != nil {
		return "", err
	}
	if utf8.RuneCountInString(passphrase) < crypt.MinPassphraseLength {
		return "", fmt.Errorf("the passphrase has fewer than %d characters. Run \"envs %s\" again with a longer passphrase", crypt.MinPassphraseLength, command)
	}
	again, err := a.ReadHidden("Repeat the passphrase: ")
	if err != nil {
		return "", err
	}
	if again != passphrase {
		return "", fmt.Errorf("the two passphrases are not equal. Run \"envs %s\" again", command)
	}
	return passphrase, nil
}

func (a *App) init(ctx context.Context, args []string) error {
	if len(args) > 1 {
		return errors.New("envs init takes one project name at most. Run \"envs init [name]\"")
	}
	var project string
	if len(args) == 1 {
		project = args[0]
		if err := names.Project(project); err != nil {
			return err
		}
	} else {
		project = strings.ToLower(filepath.Base(a.Dir))
		if names.Project(project) != nil {
			return fmt.Errorf("the folder name %q is not a valid project name. Run \"envs init <name>\" with a name of lowercase letters, digits, \".\", \"_\", and \"-\"", filepath.Base(a.Dir))
		}
	}

	se, err := a.open()
	if err != nil {
		return err
	}
	se.syncForRead(ctx, false)
	if se.store.ProjectExists(project) {
		if !a.IsTerminal() {
			return fmt.Errorf("the project %q exists in the store, and stdin is not a terminal. Run \"envs init\" in a terminal to confirm the link", project)
		}
		if err := a.confirm(fmt.Sprintf("The project %q exists in the store.\nLink this folder to it?", project)); err != nil {
			return err
		}
	}

	folder, err := link.Canonical(a.Dir)
	if err != nil {
		return err
	}
	if err := link.Write(a.Dir, project); err != nil {
		return err
	}
	if err := link.Trust(a.envsDir(), folder, project); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Linked %s to the project %q. Commit %s to the project repository.\n", folder, project, link.FileName)
	if rule := store.IgnoreRule(ctx, a.Dir, link.FileName); rule != "" {
		a.warn("git ignores %s because of the rule %s, so your other devices do not get it. %s", link.FileName, rule, unignoreHint)
	}
	return nil
}

// unignoreHint tells the user how to commit a link file that git ignores. A
// ".env*" rule, common in project templates, also matches ".envs.json".
var unignoreHint = fmt.Sprintf("Add the line \"!%s\" below that rule, then commit %s.", link.FileName, link.FileName)
