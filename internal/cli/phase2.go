package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/keycache"
	"github.com/lminii/envs/internal/store"
)

// passwd encrypts key.age again with a new passphrase. The store key and all
// secret files stay unchanged.
func (a *App) passwd(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("envs passwd takes no arguments. Run \"envs passwd\"")
	}
	se, err := a.open()
	if err != nil {
		return err
	}
	if !a.IsTerminal() {
		return errors.New("stdin is not a terminal, and envs passwd reads the passphrase from a terminal. Run \"envs passwd\" in a terminal")
	}
	current, err := a.ReadHidden("Current passphrase: ")
	if err != nil {
		return err
	}
	if _, err := se.keyFromFile(current); err != nil {
		return err
	}
	next, err := a.newPassphrase("", "passwd")
	if err != nil {
		return err
	}

	var key, keyHash string
	err = se.commit(ctx, "envs passwd", func() ([]string, error) {
		// The key comes from key.age, not from the keychain. A cached key
		// from before "envs rotate" on another device must not go into key.age.
		key, err = se.keyFromFile(current)
		if err != nil {
			return nil, err
		}
		data, err := crypt.EncryptKeyFile(next, key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(se.store.KeyPath(), data, 0o644); err != nil {
			return nil, err
		}
		keyHash = crypt.Hash(data)
		return []string{store.KeyFileName}, nil
	})
	if err != nil {
		return err
	}
	se.key, se.keyHash = key, keyHash
	se.cache()
	fmt.Fprintln(a.Stdout, "Changed the passphrase. Other devices continue with no new login.")
	fmt.Fprintln(a.Stdout, "The old key.age stays in the git history. If the old passphrase leaked, change each secret at its provider and run \"envs rotate\".")
	return nil
}

// rotate creates a new store key and encrypts key.age and all secret files
// again, in one commit.
func (a *App) rotate(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("envs rotate takes no arguments. Run \"envs rotate\"")
	}
	se, err := a.open()
	if err != nil {
		return err
	}
	if !a.IsTerminal() {
		return errors.New("stdin is not a terminal, and envs rotate reads the passphrase from a terminal. Run \"envs rotate\" in a terminal")
	}
	passphrase, err := a.ReadHidden("Passphrase: ")
	if err != nil {
		return err
	}
	if _, err := se.keyFromFile(passphrase); err != nil {
		return err
	}

	var newKey, keyHash string
	var count int
	err = se.commit(ctx, "envs rotate", func() ([]string, error) {
		oldKey, err := se.keyFromFile(passphrase)
		if err != nil {
			return nil, err
		}
		if newKey, err = crypt.NewStoreKey(); err != nil {
			return nil, err
		}
		files, err := se.store.SecretFiles()
		if err != nil {
			return nil, err
		}
		// All files are decrypted before the first write, so a file that
		// fails stops the command with no file changed.
		encrypted := make([][]byte, len(files))
		for i, rel := range files {
			t := target{filepath.Base(filepath.Dir(rel)), strings.TrimSuffix(filepath.Base(rel), ".age")}
			data, err := crypt.ReadFile(filepath.Join(se.store.Root, rel))
			if err != nil {
				return nil, se.secretFileError(t, err)
			}
			file, err := crypt.DecryptSecretFile(oldKey, data, t.project, t.environment)
			if err != nil {
				return nil, se.secretFileError(t, err)
			}
			if encrypted[i], err = crypt.EncryptSecretFile(newKey, file); err != nil {
				return nil, err
			}
		}
		keyFile, err := crypt.EncryptKeyFile(passphrase, newKey)
		if err != nil {
			return nil, err
		}

		paths := []string{store.KeyFileName}
		for i, rel := range files {
			if err := os.WriteFile(filepath.Join(se.store.Root, rel), encrypted[i], 0o644); err != nil {
				return nil, err
			}
			paths = append(paths, rel)
		}
		if err := os.WriteFile(se.store.KeyPath(), keyFile, 0o644); err != nil {
			return nil, err
		}
		keyHash, count = crypt.Hash(keyFile), len(files)
		return paths, nil
	})
	if err != nil {
		return err
	}
	se.key, se.keyHash = newKey, keyHash
	se.cache()
	fmt.Fprintf(a.Stdout, "Created a new store key and encrypted %d files again. Other devices ask for the passphrase one time.\n", count)
	fmt.Fprintln(a.Stdout, "The old store key still decrypts the old files in the git history. If the old key leaked, change each secret at its provider.")
	return nil
}

func (a *App) log(ctx context.Context, args []string) error {
	opts, positional, err := a.parse("log", args, true, true)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return errors.New("envs log takes no arguments. Run \"envs log\"")
	}
	t, err := a.resolve(opts)
	if err != nil {
		return err
	}
	se, err := a.open()
	if err != nil {
		return err
	}
	se.syncForRead(ctx, opts.offline)

	// Without --env, the history covers all environments of the project.
	path, name := t.project, t.project
	if opts.environmentSet {
		full, err := se.store.SecretPath(t.project, t.environment)
		if err != nil {
			return err
		}
		if path, err = se.store.Rel(full); err != nil {
			return err
		}
		name = t.String()
	}
	lines, err := se.store.Log(ctx, path)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("the store has no history for %s. Run \"envs set <KEY>\" to add a value", name)
	}
	for _, line := range lines {
		when, subject, _ := strings.Cut(line, "\t")
		fmt.Fprintf(a.Stdout, "%s  %s\n", when, printable(subject))
	}
	return nil
}

// printable replaces control characters. A commit subject comes from the
// remote, and a person with write access can put terminal escape sequences in it.
func printable(text string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return '?'
		}
		return r
	}, text)
}

// logout removes the cached store key and the local clone. The trusted
// folder list stays.
func (a *App) logout(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("envs logout takes no arguments. Run \"envs logout\"")
	}
	var remoteURL string
	if s, err := store.Open(a.storeDir()); err == nil {
		remoteURL, _ = s.RemoteURL(ctx)
	}
	if err := keycache.Delete(); err != nil {
		a.warn("cannot remove the store key from the OS keychain (%v).", err)
	}
	if err := os.RemoveAll(a.storeDir()); err != nil {
		return fmt.Errorf("cannot remove the store: %v. Close programs that use %s and run \"envs logout\" again", err, a.storeDir())
	}
	fmt.Fprintln(a.Stdout, "Logged out. The store key and the local store are removed from this device.")
	if remoteURL != "" {
		fmt.Fprintf(a.Stdout, "Run \"envs login %s\" to log in again.\n", printable(remoteURL))
	}
	return nil
}
