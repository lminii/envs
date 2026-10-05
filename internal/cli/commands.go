package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/lminii/envs/internal/crypt"
	"github.com/lminii/envs/internal/names"
	"github.com/lminii/envs/internal/runner"
)

func (a *App) set(ctx context.Context, args []string) error {
	opts, positional, err := a.parse("set", args, false, true)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("envs set takes one key name and no value. Run \"envs set <KEY>\" and type the value at the prompt, or send it through stdin")
	}
	key := positional[0]
	if err := names.Key(key); err != nil {
		return err
	}
	t, err := a.resolve(opts)
	if err != nil {
		return err
	}
	se, err := a.open()
	if err != nil {
		return err
	}

	value, err := a.readValue(key)
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("the value is empty. Run \"envs set\" again with a value, or run \"envs rm\" to delete the key")
	}
	if err := checkValue(value); err != nil {
		return fmt.Errorf("%v. Run \"envs set\" again with a value without it", err)
	}

	err = se.write(ctx, t, fmt.Sprintf("envs set %s %s", t, key), func(file *crypt.SecretFile) error {
		if err := checkCase(file, key); err != nil {
			return err
		}
		file.Values[key] = value
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Set %s in %s\n", key, t)
	return nil
}

// readValue reads from a hidden prompt on a terminal and from stdin
// otherwise. A stdin value loses one trailing line ending and nothing else.
func (a *App) readValue(key string) (string, error) {
	if a.IsTerminal() {
		return a.ReadHidden(fmt.Sprintf("Value of %s: ", key))
	}
	data, err := io.ReadAll(a.Stdin)
	if err != nil {
		return "", err
	}
	value := string(data)
	if strings.HasSuffix(value, "\r\n") {
		return value[:len(value)-2], nil
	}
	return strings.TrimSuffix(value, "\n"), nil
}

// checkValue rejects a value that an environment variable or the JSON file
// cannot hold. The error never contains the value.
func checkValue(value string) error {
	if strings.ContainsRune(value, 0) {
		return errors.New("the value contains a NUL byte, and an environment variable cannot hold it")
	}
	if !utf8.ValidString(value) {
		return errors.New("the value is not valid UTF-8, and the store cannot hold it")
	}
	return nil
}

// checkCase rejects a key that differs only by case from a key in the file,
// because Windows environment names ignore case.
func checkCase(file *crypt.SecretFile, key string) error {
	for existing := range file.Values {
		if existing != key && strings.EqualFold(existing, key) {
			return fmt.Errorf("the key %q differs only by case from the key %q. Use %q, or run \"envs rm %s\" first", key, existing, existing, existing)
		}
	}
	return nil
}

func (a *App) rm(ctx context.Context, args []string) error {
	opts, positional, err := a.parse("rm", args, false, true)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("envs rm takes one key name. Run \"envs rm <KEY>\"")
	}
	key := positional[0]
	if err := names.Key(key); err != nil {
		return err
	}
	t, err := a.resolve(opts)
	if err != nil {
		return err
	}
	se, err := a.open()
	if err != nil {
		return err
	}
	err = se.write(ctx, t, fmt.Sprintf("envs rm %s %s", t, key), func(file *crypt.SecretFile) error {
		if _, ok := file.Values[key]; !ok {
			return fmt.Errorf("%s has no key %q. Run \"envs list\" to see the keys", t, key)
		}
		delete(file.Values, key)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Removed %s from %s\n", key, t)
	return nil
}

func (a *App) importFile(ctx context.Context, args []string) error {
	opts, positional, err := a.parse("import", args, false, true)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("envs import takes one file. Run \"envs import <file>\"")
	}
	source := positional[0]
	if !filepath.IsAbs(source) {
		source = filepath.Join(a.Dir, source)
	}
	t, err := a.resolve(opts)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("cannot read the file: %v. Run \"envs import <file>\" with a dotenv file", err)
	}
	entries, err := parseDotenv(data)
	if err != nil {
		return fmt.Errorf("%s: %v. Correct the file and run \"envs import\" again", positional[0], err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s has no keys. Run \"envs import <file>\" with a dotenv file", positional[0])
	}
	se, err := a.open()
	if err != nil {
		return err
	}

	keys := map[string]bool{}
	err = se.write(ctx, t, fmt.Sprintf("envs import %s", t), func(file *crypt.SecretFile) error {
		for _, e := range entries {
			if err := checkCase(file, e.key); err != nil {
				return fmt.Errorf("%s: line %d: %v", positional[0], e.line, err)
			}
			file.Values[e.key] = e.value
			keys[e.key] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "Imported %d keys into %s\n", len(keys), t)
	a.warn("%s still exists and holds the values in plaintext. Delete it. A deleted file is recoverable from the disk.", positional[0])
	return nil
}

func (a *App) list(ctx context.Context, args []string) error {
	opts, positional, err := a.parse("list", args, true, true)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return errors.New("envs list takes no arguments. Run \"envs list\"")
	}
	file, err := a.read(ctx, opts)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(file.Values))
	for key := range file.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintln(a.Stdout, key)
	}
	return nil
}

func (a *App) run(ctx context.Context, args []string) (int, error) {
	opts, argv, err := a.parse("run", args, true, false)
	if err != nil {
		return 0, err
	}
	if len(argv) == 0 {
		return 0, errors.New("envs run needs a command. Run \"envs run -- <command>\"")
	}
	file, err := a.read(ctx, opts)
	if err != nil {
		return 0, err
	}
	return runner.Run(argv, file.Values)
}

// read syncs and decrypts the secret file of a read command.
func (a *App) read(ctx context.Context, opts options) (*crypt.SecretFile, error) {
	t, err := a.resolve(opts)
	if err != nil {
		return nil, err
	}
	se, err := a.open()
	if err != nil {
		return nil, err
	}
	se.syncForRead(ctx, opts.offline)
	file, exists, err := se.load(t)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("the store has no values for %s. Run \"envs set <KEY>\" to add one", t)
	}
	return file, nil
}
