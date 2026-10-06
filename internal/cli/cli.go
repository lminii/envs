// Package cli parses the command line, asks the user for input, and prints output.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/lminii/envs/internal/link"
	"github.com/lminii/envs/internal/names"
)

const defaultEnvironment = "dev"

const usage = `envs syncs encrypted development secrets through a private git repository.

Usage:
  envs login <repo-url>     Clone the store. Create or unlock the store key.
  envs init [name]          Link the current folder to a project.
  envs set <KEY>            Store a value from a hidden prompt or from stdin.
  envs list                 Print the key names.
  envs rm <KEY>             Delete a key.
  envs run -- <command>     Run a command with the stored values in its environment.
  envs import <file>        Store all keys of a dotenv file.
  envs log                  Show the change history of the project.
  envs passwd               Change the passphrase.
  envs rotate               Create a new store key and encrypt all files again.
  envs logout               Remove the store key and the store from this device.

Flags for set, list, rm, run, import, and log:
  --env <name>              Environment. The default is "dev".
  --project <name>          Project. The default comes from .envs.json.

Flag for list, run, and log:
  --offline                 Do not sync with the remote first.
`

// App holds the process context of one command. Tests replace the fields.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Dir is the current folder.
	Dir string
	// Home is the home folder of the user. The tool keeps its files in Home/.envs.
	Home string

	IsTerminal func() bool
	// ReadHidden shows prompt and reads one line with echo off.
	ReadHidden func(prompt string) (string, error)
	// ReadLine shows prompt and reads one line.
	ReadLine func(prompt string) (string, error)
}

// Main runs the command in os.Args and returns the exit code.
func Main() int {
	app := &App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	app.IsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	app.ReadHidden = func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		defer fmt.Fprintln(os.Stderr)
		fd := int(os.Stdin.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			value, err := term.ReadPassword(fd)
			return string(value), err
		}
		defer term.Restore(fd, state)
		return readMasked(os.Stdin, os.Stderr)
	}
	app.ReadLine = func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		return readLine(os.Stdin)
	}

	var err error
	if app.Dir, err = os.Getwd(); err != nil {
		fmt.Fprintf(os.Stderr, "envs: cannot find the current folder: %v\n", err)
		return 1
	}
	if app.Home, err = os.UserHomeDir(); err != nil {
		fmt.Fprintf(os.Stderr, "envs: cannot find the home folder: %v\n", err)
		return 1
	}
	return app.Run(os.Args[1:])
}

// Run runs one command and returns the exit code.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return 1
	}
	ctx := context.Background()
	code := 0
	var err error
	switch command, rest := args[0], args[1:]; command {
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, usage)
	case "login":
		err = a.login(ctx, rest)
	case "init":
		err = a.init(ctx, rest)
	case "set":
		err = a.set(ctx, rest)
	case "list":
		err = a.list(ctx, rest)
	case "rm":
		err = a.rm(ctx, rest)
	case "run":
		code, err = a.run(ctx, rest)
	case "import":
		err = a.importFile(ctx, rest)
	case "passwd":
		err = a.passwd(ctx, rest)
	case "rotate":
		err = a.rotate(ctx, rest)
	case "log":
		err = a.log(ctx, rest)
	case "logout":
		err = a.logout(ctx, rest)
	default:
		err = fmt.Errorf("unknown command %q. Run \"envs help\" to see the commands", command)
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "envs: %v\n", err)
		return 1
	}
	return code
}

func (a *App) envsDir() string {
	return filepath.Join(a.Home, ".envs")
}

func (a *App) storeDir() string {
	return filepath.Join(a.envsDir(), "store")
}

func (a *App) warn(format string, args ...any) {
	fmt.Fprintf(a.Stderr, "envs: warning: "+format+"\n", args...)
}

// target is the project and environment of one command.
type target struct {
	project     string
	environment string
}

func (t target) String() string {
	return t.project + "/" + t.environment
}

type options struct {
	project     string
	environment string
	// environmentSet is true when the command line has --env.
	environmentSet bool
	offline        bool
}

// parse reads the flags of a project command. With interspersed set, flags
// can follow positional arguments. "envs run" does not set it, so the flags
// of the child command stay with the child.
func (a *App) parse(command string, args []string, withOffline, interspersed bool) (options, []string, error) {
	var opts options
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.environment, "env", defaultEnvironment, "")
	fs.StringVar(&opts.project, "project", "", "")
	if withOffline {
		fs.BoolVar(&opts.offline, "offline", false, "")
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return opts, nil, fmt.Errorf("%v. Run \"envs help\" to see the flags", err)
		}
		args = fs.Args()
		if !interspersed || len(args) == 0 {
			positional = append(positional, args...)
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	if err := names.Environment(opts.environment); err != nil {
		return opts, nil, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "env" {
			opts.environmentSet = true
		}
	})
	return opts, positional, nil
}

// resolve returns the project and environment of the command. A project from
// a link file needs a trusted folder (PRD 8.6). --project does not.
func (a *App) resolve(opts options) (target, error) {
	t := target{project: opts.project, environment: opts.environment}
	if t.project != "" {
		return t, names.Project(t.project)
	}
	folder, project, err := link.Find(a.Dir)
	if errors.Is(err, link.ErrNotFound) {
		return t, errors.New("no link file found. Run \"envs init\" in the project folder or pass --project")
	}
	if err != nil {
		return t, err
	}
	t.project = project

	// The check uses the folder of the link file, not the current folder.
	folder, err = link.Canonical(folder)
	if err != nil {
		return t, err
	}
	trusted, err := link.IsTrusted(a.envsDir(), folder, project)
	if err != nil || trusted {
		return t, err
	}
	if !a.IsTerminal() {
		return t, fmt.Errorf("the folder %s links to the project %q and is not a trusted folder, and stdin is not a terminal. Run an envs command in a terminal in that folder to confirm it, or pass --project %s", folder, project, project)
	}
	prompt := fmt.Sprintf("The folder %s is not a trusted folder.\nIts link file names the project %q.\nUse the secrets of this project in this folder?", folder, project)
	if err := a.confirm(prompt); err != nil {
		return t, err
	}
	return t, link.Trust(a.envsDir(), folder, project)
}

// confirm continues only on the exact answer "yes". The caller makes sure
// that stdin is a terminal.
func (a *App) confirm(prompt string) error {
	answer, err := a.ReadLine(prompt + " Type \"yes\" to continue: ")
	if err != nil {
		return err
	}
	if answer != "yes" {
		return errors.New("stopped, because the answer was not \"yes\". Run the command again and answer \"yes\" to continue")
	}
	return nil
}

// readLine reads one line without a read past the line ending, so a later
// hidden prompt gets the next line.
func readLine(r io.Reader) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return string(line), nil
}
