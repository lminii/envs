# envs

`envs` syncs local development secrets across devices through a private git repository.
Secrets are encrypted at rest and injected into a child process at run time.
There is no server, no account, and no plaintext `.env` file on disk.

```sh
envs login git@github.com:you/envs-store.git   # once per device
envs init                                       # once per project
envs set API_KEY                                # hidden prompt
envs run -- bun run dev                         # every time
```

## Why

Working on more than one machine means copying `.env` files around by hand. They go stale, and they sit on disk in plaintext.
Hosted secret managers fix that, but they need an account and a server, and some need a key file you still have to copy.

`envs` is a small CLI for local development only. It keeps one encrypted copy of each project's secrets in a private git repo you already have, and a new machine needs just that repo and a passphrase.

It is built for one developer on several machines. It has no team features.

## Install

Download the binary for your platform from the [latest release](https://github.com/lminii/envs/releases/latest) and check it against `SHA256SUMS`:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
chmod +x envs-darwin-arm64
mv envs-darwin-arm64 ~/.local/bin/envs
```

On macOS, a binary downloaded with a browser is quarantined. Clear it with `xattr -d com.apple.quarantine ~/.local/bin/envs`.

Or build from source with Go:

```sh
go install github.com/lminii/envs@v0.1.0
```

`envs` needs git 2.30 or later on the `PATH`.

## Usage

**First device.** Create an empty private repository, then:

```sh
envs login <repo-url>
```

The tool asks for a new passphrase (16 characters minimum), creates the store key, and pushes it.

**Another device.** Run the same command. The tool clones the store and asks for the passphrase once.

**A project.** In the project folder:

```sh
envs init                # writes .envs.json, commit this file
envs import .env         # store every key from an existing file
rm .env
envs run -- bun run dev
```

The first `envs run` in a folder on a new device asks you to confirm the folder before it injects anything.

| Command | What it does |
| --- | --- |
| `envs login <repo-url>` | Clone the store. Create or unlock the store key. |
| `envs init [name]` | Link the current folder to a project. |
| `envs set <KEY>` | Store a value from a hidden prompt or from stdin. |
| `envs list` | Print key names. |
| `envs rm <KEY>` | Delete a key. |
| `envs run -- <cmd>` | Run a command with the stored values in its environment. |
| `envs import <file>` | Store all keys from a dotenv file. |
| `envs log` | Show the change history of the project. |
| `envs passwd` | Change the passphrase. |
| `envs rotate` | Create a new store key and re-encrypt every file. |
| `envs logout` | Remove the cached key and the local store. |

Project commands take `--env <name>` (default `dev`) and `--project <name>`.
`run`, `list`, and `log` take `--offline` to skip the sync.

There is no command that prints a value.

## How it works

```
~/.envs/store/            clone of your private repo
├── key.age               store key, encrypted with your passphrase
└── portfolio/
    └── dev.age           {"version", "project", "environment", "values"}, encrypted with the store key
```

- The store key is 32 random bytes. Each `<project>/<env>.age` file is encrypted with it.
- `key.age` is the store key encrypted with your passphrase. Changing the passphrase rewrites only this file.
- After the first unlock, the store key is cached in the OS keychain. You don't type the passphrase again on that device.
- Every read does a fetch (5 s timeout) and a fast-forward-only merge. If that fails, the command uses the local copy and warns.
- Every write is sync, decrypt, change, encrypt, commit, push. A rejected push discards the local commit and retries, up to 3 times. Unpushed commits are never kept.
- `envs run` decrypts in memory, adds the values to the parent environment, and starts the command directly with no shell. Signals and the exit code pass through.

## Stack choices

**Go.** One static binary per platform with `CGO_ENABLED=0`, cross-compiled from one CI job. A secrets tool shouldn't need a language runtime installed, and the standard library covers process management, signals, and file handling on all three OSes.

**[age](https://github.com/FiloSottile/age) in passphrase mode.** No custom cryptography. Passphrase mode is authenticated, so only a holder of the store key can produce a file the tool accepts. A public-key design would let anyone with the public key write a valid file into the store. The store key has 256 bits of entropy, so secret files use a low scrypt work factor. `key.age` uses age's default factor because it protects a human passphrase.

**The system `git` binary.** The store is a plain git repo. That gives sync, full history, and rollback for free, and it reuses the SSH keys or credential helper you already have. Git is started with an argument list, never through a shell, with `--` before every path and URL.

**OS keychain via [go-keyring](https://github.com/zalando/go-keyring).** macOS Keychain, Windows Credential Manager, and the Secret Service on Linux. The store key is never written to a plain file. With no keychain available, the tool asks for the passphrase on every command.

**JSON inside the encrypted files, not dotenv.** A dotenv writer with a quoting bug lets a value containing a newline add a second variable. JSON doesn't have that failure mode. `envs import` still reads dotenv files.

**No server.** The git host you already trust is the only shared component. There is nothing to run, pay for, or keep online.

## Security

The full threat model is in [PRD.md section 9](PRD.md#9-security). Each listed threat has a test in [`internal/cli/threat_test.go`](internal/cli/threat_test.go). A review of the design is in [docs/security-review.md](docs/security-review.md).

What it protects against:

- Someone reading the store repo. Every value is encrypted.
- Someone with write access forging a file, moving a file to another project, raising the scrypt cost to stall the tool, or rewriting history.
- A cloned project whose `.envs.json` names one of your projects. Unknown folders need confirmation.
- Values leaking to scrollback or shell history. Values are never printed or passed as arguments.

What it does not protect against:

- Offline passphrase guessing by anyone with a copy of the repo. Use a long random passphrase used nowhere else.
- Software running as your user. It can read the keychain and the child process environment.
- The git host seeing project names, environment names, key names in commit messages, and commit times.
- A leaked passphrase. Old `key.age` files stay in git history, so `envs passwd` alone doesn't revoke it. Rotate the real secrets at each provider, then run `envs passwd` and `envs rotate`.

`envs` is for development secrets. For production, use the secret manager of your CI or host, such as GitHub Actions secrets.

## Development

```sh
go vet ./...
go test -race ./...
```

Tests run against local bare git repositories, so they need git but no network.
Pushing a `v*` tag runs the tests on Linux and macOS, then builds the release binaries and `SHA256SUMS`.
