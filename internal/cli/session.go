package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/keycache"
	"github.com/lminii/envs/internal/store"
)

const maxWriteAttempts = 3

// session is the open store and the store key of one command.
type session struct {
	app   *App
	store *store.Store
	key   string
	// keyHash is the SHA-256 of the key.age that key came from.
	keyHash string
}

func (a *App) open() (*session, error) {
	s, err := store.Open(a.storeDir())
	if errors.Is(err, store.ErrNoStore) {
		return nil, errors.New("this device has no store. Run \"envs login <repo-url>\"")
	}
	if err != nil {
		return nil, err
	}
	return &session{app: a, store: s}, nil
}

// syncForRead syncs before a read. A failure is a warning, and the command
// uses the local clone.
func (se *session) syncForRead(ctx context.Context, offline bool) {
	if offline {
		return
	}
	err := se.store.Sync(ctx, true)
	switch {
	case errors.Is(err, store.ErrNonFastForward):
		se.app.warn("the remote history changed. It does not continue the local history, so the store was changed outside envs. The command uses the local copy. Examine the remote repository before you run \"envs logout\" and \"envs login\" to accept it.")
	case err != nil:
		se.app.warn("cannot sync the store (%v). The command uses the local copy.", err)
	}
}

func (se *session) syncForWrite(ctx context.Context) error {
	err := se.store.Sync(ctx, false)
	switch {
	case errors.Is(err, store.ErrNonFastForward):
		return errors.New("the remote history changed. It does not continue the local history, so the store was changed outside envs. Examine the remote repository, then run \"envs logout\" and \"envs login\" to accept it")
	case err != nil:
		return fmt.Errorf("cannot sync the store (%v). A write needs the remote. Connect to the network and run the command again", err)
	}
	return nil
}

// unlock gets the store key from the keychain. When the keychain has no
// usable entry, for any reason, it asks for the passphrase.
func (se *session) unlock() error {
	if se.key != "" {
		return nil
	}
	if key, hash, ok := keycache.Get(); ok {
		se.key, se.keyHash = key, hash
		return nil
	}
	return se.unlockWithPassphrase()
}

func (se *session) unlockWithPassphrase() error {
	data, err := crypt.ReadFile(se.store.KeyPath())
	if err != nil {
		return se.keyFileError(err)
	}
	if !se.app.IsTerminal() {
		return errors.New("the store key is not in the OS keychain, and stdin is not a terminal. Run an envs command in a terminal to enter the passphrase")
	}
	passphrase, err := se.app.ReadHidden("Passphrase: ")
	if err != nil {
		return err
	}
	key, err := crypt.DecryptKeyFile(passphrase, data)
	if err != nil {
		return se.keyFileError(err)
	}
	se.key, se.keyHash = key, crypt.Hash(data)
	se.cache()
	return nil
}

func (se *session) cache() {
	if err := keycache.Set(se.key, se.keyHash); err != nil {
		se.app.warn("cannot save the store key in the OS keychain (%v). envs asks for the passphrase on each command.", err)
	}
}

func (se *session) keyFileError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("the store has no key.age. The store was changed outside envs. Restore key.age from the git history in %s", se.store.Root)
	case errors.Is(err, crypt.ErrWrongKey):
		return errors.New("the passphrase is wrong. Run the command again")
	case errors.Is(err, crypt.ErrTooLarge), errors.Is(err, crypt.ErrDamaged):
		return fmt.Errorf("cannot use key.age: %v. The store was changed outside envs. Restore key.age from the git history in %s", err, se.store.Root)
	}
	return err
}

// currentKeyHash returns the hash of key.age in the local clone, or "" when
// the file is not readable.
func (se *session) currentKeyHash() string {
	data, err := crypt.ReadFile(se.store.KeyPath())
	if err != nil {
		return ""
	}
	return crypt.Hash(data)
}

// load decrypts the secret file of t. exists is false when the store has no
// such file. load applies the key.age hash rule.
func (se *session) load(t target) (file *crypt.SecretFile, exists bool, err error) {
	if err := se.unlock(); err != nil {
		return nil, false, err
	}
	path, err := se.store.SecretPath(t.project, t.environment)
	if err != nil {
		return nil, false, err
	}
	current := se.currentKeyHash()

	data, err := crypt.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		// No file proves that the cached key is the current one. A key from
		// before "envs rotate" must not encrypt a new file.
		if current != se.keyHash {
			if err := se.unlockWithPassphrase(); err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, se.secretFileError(t, err)
	}

	file, err = crypt.DecryptSecretFile(se.key, data, t.project, t.environment)
	if errors.Is(err, crypt.ErrWrongKey) && current != se.keyHash {
		if err := se.unlockWithPassphrase(); err != nil {
			return nil, false, err
		}
		file, err = crypt.DecryptSecretFile(se.key, data, t.project, t.environment)
	}
	if err != nil {
		return nil, false, se.secretFileError(t, err)
	}
	if current != "" && current != se.keyHash {
		se.keyHash = current
		se.cache()
	}
	return file, true, nil
}

func (se *session) secretFileError(t target, err error) error {
	restore := fmt.Sprintf("The store was changed outside envs. Restore the file from the git history in %s", se.store.Root)
	switch {
	case errors.Is(err, crypt.ErrWrongKey):
		return fmt.Errorf("the store key cannot decrypt %s.age. %s", t, restore)
	case errors.Is(err, crypt.ErrTooLarge), errors.Is(err, crypt.ErrDamaged):
		return fmt.Errorf("cannot use %s.age: %v. %s", t, err, restore)
	}
	return fmt.Errorf("cannot use %s.age: %v", t, err)
}

// write changes the secret file of t with the write sequence.
func (se *session) write(ctx context.Context, t target, message string, change func(file *crypt.SecretFile) error) error {
	return se.commit(ctx, message, func() ([]string, error) {
		file, exists, err := se.load(t)
		if err != nil {
			return nil, err
		}
		if !exists {
			file = crypt.NewSecretFile(t.project, t.environment)
		}
		if err := change(file); err != nil {
			return nil, err
		}
		data, err := crypt.EncryptSecretFile(se.key, file)
		if err != nil {
			return nil, err
		}
		if len(data) > crypt.MaxFileSize {
			return nil, fmt.Errorf("%s would be larger than 1 MiB. Store smaller values, or use more than one environment", t)
		}
		path, err := se.store.SecretPath(t.project, t.environment)
		if err != nil {
			return nil, err
		}
		rel, err := se.store.Rel(path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
		return []string{rel}, nil
	})
}

// keyFromFile opens the key.age of the local clone with passphrase.
func (se *session) keyFromFile(passphrase string) (string, error) {
	data, err := crypt.ReadFile(se.store.KeyPath())
	if err != nil {
		return "", se.keyFileError(err)
	}
	key, err := crypt.DecryptKeyFile(passphrase, data)
	if err != nil {
		return "", se.keyFileError(err)
	}
	return key, nil
}

// commit runs the write sequence: sync, build, commit, push.
// build changes files in the clone and returns their paths, relative to the
// store root. After a rejected push, commit discards the local commit and
// starts again, so build runs on the new remote state.
func (se *session) commit(ctx context.Context, message string, build func() (paths []string, err error)) error {
	for attempt := 1; ; attempt++ {
		if err := se.syncForWrite(ctx); err != nil {
			return err
		}
		paths, err := build()
		if err != nil {
			se.store.Restore(ctx)
			return err
		}
		if err := se.store.Commit(ctx, message, paths...); err != nil {
			se.store.Restore(ctx)
			return err
		}

		pushErr := se.store.Push(ctx)
		if pushErr == nil {
			return nil
		}
		if err := se.store.Discard(ctx); err != nil {
			return fmt.Errorf("%v. The change was not stored. Connect to the network and run the command again", pushErr)
		}
		if attempt == maxWriteAttempts {
			return fmt.Errorf("the remote rejected the push %d times (%v). The change was not stored. Run the command again", maxWriteAttempts, pushErr)
		}
	}
}
