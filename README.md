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

With Homebrew on macOS or Linux:

```sh
brew install lminii/tap/envs
```

`brew upgrade envs` picks up new releases.

Without Homebrew, download the binary for your platform from the [latest release](https://github.com/lminii/envs/releases/latest), check it against `SHA256SUMS`, and put it on your `PATH`:

```sh
grep envs-darwin-arm64 SHA256SUMS | shasum -a 256 -c -
chmod +x envs-darwin-arm64
mv envs-darwin-arm64 ~/.local/bin/envs
```

On macOS, a binary downloaded with a browser is quarantined. Clear it with `xattr -d com.apple.quarantine ~/.local/bin/envs`.

Or build from source with Go:

```sh
go install github.com/lminii/envs@latest
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

Commit `.envs.json` so other devices skip `envs init`. Many project templates ignore `.env*`, which also matches `.envs.json`. `envs init` warns when that happens. Add an exception below the rule:

```gitignore
.env*
!.envs.json
```

To avoid typing `envs run --` every time, put it in the dev script:

```json
"scripts": { "dev": "envs run -- next dev" }
```

Keep it out of build scripts that run in CI, because CI has no store.

`envs status` shows what this device and folder have: the store, sync, the cached key, the linked project, whether the folder is trusted, whether the link file is committed, and how many values are stored. It never prompts, so run it first when something doesn't work.

| Command | What it does |
| --- | --- |
| `envs login <repo-url>` | Clone the store. Create or unlock the store key. |
| `envs init [name]` | Link the current folder to a project. |
| `envs set <KEY>` | Store a value from a hidden prompt or from stdin. |
| `envs list` | Print key names. |
| `envs rm <KEY>` | Delete a key. |
| `envs run -- <cmd>` | Run a command with the stored values in its environment. |
| `envs status` | Show the store, the project, and what is missing. |
| `envs import <file>` | Store all keys from a dotenv file. |
| `envs log` | Show the change history of the project. |
| `envs passwd` | Change the passphrase. |
| `envs rotate` | Create a new store key and re-encrypt every file. |
| `envs logout` | Remove the cached key and the local store. |

Project commands take `--env <name>` (default `dev`) and `--project <name>`.
`run`, `list`, `status`, and `log` take `--offline` to skip the sync.

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

Each threat below has a test in [`internal/cli/threat_test.go`](internal/cli/threat_test.go).

| Threat | Control | Test |
| --- | --- | --- |
| Someone reads the store repo, for example after a git host breach. | Every value is encrypted. The store key is locked by scrypt and a passphrase of 16 characters or more. | `StoreRead` |
| Someone with write access adds a file with values of their choice. | Authenticated encryption. Only the store key can create a file the tool accepts. | `ForgedFile` |
| Someone copies a file from one project to another. | After decryption, the project and environment names must match the file path. | `MovedFile` |
| Someone deletes `key.age` so a new device creates a new key. | Login refuses a store that has secret files and no `key.age`. | `DeletedKeyFile` |
| Someone raises the scrypt work factor in a header, or adds a huge file. | Work factor and 1 MiB size caps, checked before decryption. | `WorkFactorAndSize` |
| Someone corrupts a file so the tool asks for the passphrase. | The cached `key.age` hash tells a rotation apart from tampering. The tool reports tampering instead of asking. | `CorruptedFile` |
| Someone rewrites the store history. | Fast-forward-only sync, with a warning that the history changed. | `RewrittenHistory` |
| A cloned project has a `.envs.json` that names one of your projects. | Unknown folders need confirmation before any value is injected. | `UntrustedLinkFile` |
| A repo cloned inside a trusted project inherits its link file. | The link file search stops at the first `.git`. | `NestedRepository` |
| A project contains a program with the same name as your dev command. | `envs run` never starts a program from the current folder without an explicit path. | `CurrentFolderProgram` |
| A name or URL that changes a file path or a git command. | Strict name rules, git started without a shell, `--` before every argument. | `HostileNames` |
| A value shows up in scrollback, logs, or shell history. | No command prints a value, the prompt is hidden, values are never arguments. | `ValueDisclosure` |
| A plaintext copy stays on disk. | The tool writes no plaintext file. `envs import` warns about the source file. | `PlaintextOnDisk` |

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

## Releasing

Push a version tag from an up-to-date `main`:

```sh
git switch main && git pull
git tag -a v0.3.0 -m v0.3.0
git push origin v0.3.0
```

The tag starts [`.github/workflows/release.yml`](.github/workflows/release.yml), which runs three jobs in order:

1. **test**: `gofmt`, `go vet`, `go test -race`, and `govulncheck` on Linux and macOS.
2. **release**: builds the 6 binaries with `CGO_ENABLED=0`, writes `SHA256SUMS`, and creates the GitHub release with generated notes.
3. **homebrew**: runs [`scripts/homebrew-formula.sh`](scripts/homebrew-formula.sh) with the new checksums and pushes `Formula/envs.rb` to [lminii/homebrew-tap](https://github.com/lminii/homebrew-tap).

Watch it with `gh run watch`. When it finishes, `brew upgrade envs` installs the new version.

The homebrew job needs the `HOMEBREW_TAP_TOKEN` secret on this repo: a fine-grained token with Contents read and write on `lminii/homebrew-tap` only. Without it, the job skips with a warning and the release itself still succeeds. When the token expires, create a new one with the same scope and run `gh secret set HOMEBREW_TAP_TOKEN -R lminii/envs`.

Don't rerun the homebrew job of an old release. It checks out that release's tag, so it uses that tag's version of the formula script. To fix the formula by hand, run the script from `main` and push the result to the tap:

```sh
gh release download v0.3.0 -p SHA256SUMS -O /tmp/SHA256SUMS
scripts/homebrew-formula.sh 0.3.0 /tmp/SHA256SUMS > ../homebrew-tap/Formula/envs.rb
```

Check a formula change with `brew audit --strict lminii/tap/envs`.
