# envs - Product Requirements Document

Status: Final
Date: 2026-10-05
Owner: Tyler

## 1. Summary

`envs` is a command-line tool that syncs local development secrets across devices.
It stores encrypted files in a private git repository.
It injects secrets into a child process at run time.
It has no server and no web interface.

## 2. Problem

Cloudflare Worker secrets are write-only.
A developer cannot pull them to a second device.
Local secrets live in `.dev.vars` or `.env` files, which git must not track.
The developer copies these files between devices by hand.
The copies become stale, and plaintext secrets stay on disk.

## 3. Goals

- Set up a new device with one command and one passphrase.
- Run any dev command with secrets injected, with no plaintext file on disk.
- Keep one source of truth for each project and environment.
- Keep a full change history with rollback.
- Ship one binary with no runtime dependency except git.

## 4. Non-goals

- No team features: no users, roles, or sharing.
- No server, daemon, or web interface.
- No management of production secrets. Production values stay in `wrangler secret put`.
- No custom cryptography.
- No sync of non-secret configuration. That belongs in `wrangler.jsonc` under `vars`.
- No command that shows a secret value.
- No package manager distribution. Release binaries are sufficient.

## 5. User

One developer who works on many projects from more than one device.
The devices run Windows, macOS, or Linux.
The developer already has git and a git host account.

## 6. Main flows

### 6.1 First device

1. The user creates an empty private git repository.
2. The user runs `envs login <repo-url>`.
3. The tool clones the repository and finds it empty.
4. The tool asks for a new passphrase two times.
5. The tool creates the store key, encrypts it with the passphrase, and pushes.
6. The tool caches the store key in the OS keychain.

### 6.2 New device

1. The user runs `envs login <repo-url>`.
2. The tool clones the repository and finds `key.age`.
3. The tool asks for the passphrase one time.
4. The tool caches the store key in the OS keychain.

### 6.3 Existing project

1. The user runs `envs init` in the project folder.
2. The user runs `envs import .dev.vars`.
3. The user deletes `.dev.vars`.
4. The user runs `envs run -- npx wrangler dev` to start work.

### 6.4 Daily use

1. The user runs `envs set API_KEY` to add or change a value.
2. The user runs `envs run -- <command>` to start work.

## 7. Commands

| Command | Function | Phase |
| --- | --- | --- |
| `envs login <repo-url>` | Clone the store. Create or unlock the store key. | 1 |
| `envs init [name]` | Link the current folder to a project. The default name is the folder name in lowercase. | 1 |
| `envs set <KEY>` | Read the value from a hidden prompt or from stdin. Encrypt and push. | 1 |
| `envs list` | Print key names only. | 1 |
| `envs rm <KEY>` | Delete one key and push. | 1 |
| `envs run -- <command>` | Decrypt in memory, inject, and run the command. | 1 |
| `envs import <file>` | Read a dotenv file and store all its keys. | 1 |
| `envs passwd` | Change the passphrase. | 2 |
| `envs rotate` | Create a new store key and encrypt all files again, in one commit. | 2 |
| `envs log` | Show the change history of the current project. | 2 |
| `envs logout` | Remove the cached store key and the local clone. | 2 |

All commands that touch a project accept `--env <name>`.
The default environment is `dev`.
All commands that touch a project accept `--project <name>` to override the link file.

## 8. Functional requirements

### 8.1 Store

- The store is a git repository cloned to `~/.envs/store`.
- Each project and environment pair is one file: `<project>/<environment>.age`.
- The decrypted content of a file is a JSON object.
- The JSON object contains the project name, the environment name, and a map of key names to values.
- The file `key.age` holds the store key, encrypted with the passphrase.
- The store contains no other key material.

JSON replaces dotenv syntax for the stored content.
A dotenv writer with a quoting defect lets a value with a line break add a second variable.
JSON does not have this risk.

### 8.2 Names

- A project name and an environment name must match `^[a-z0-9][a-z0-9._-]*$`.
- A project name and an environment name must not contain `..`.
- A key name must match `^[A-Za-z_][A-Za-z0-9_]*$`.
- The tool rejects any other name before it touches the store.

Lowercase names prevent collisions on file systems that ignore case.
The rules also prevent a file path outside the store.

### 8.3 Encryption

- The tool uses the `filippo.io/age` library for all encryption.
- The store key is 32 random bytes from the cryptographic random source of the operating system.
- Secret files are encrypted with age passphrase mode, with the store key as the passphrase.
- Secret files use a low scrypt work factor, because the store key has 256 bits of entropy.
- `key.age` is encrypted with age passphrase mode, with the user passphrase and the default work factor.
- The tool rejects a secret file whose scrypt work factor is above the value the tool writes.
- The tool rejects `key.age` with a work factor above 2^20.
- The tool rejects an `.age` file larger than 1 MiB before it parses the file.
- After decryption, the tool compares the project and environment names in the JSON with the file path.
- If the names do not match, the tool stops with an error.

The work factor is stored in the file header and is applied before the authentication check.
Without a cap, a changed header forces a 2^22 scrypt, which costs about 4 GiB of memory and 15 seconds per file.

Passphrase mode is authenticated.
Only a holder of the store key can create a file that the tool accepts.
A public-key design does not give this property, because any holder of the public key can create a valid file.

A passphrase change encrypts only `key.age` again.
All secret files stay unchanged.

### 8.4 Key cache

- The tool stores the store key in the OS keychain with `zalando/go-keyring`.
- On Windows, the keychain is Windows Credential Manager.
- If no keychain is available, the tool asks for the passphrase on each command.
- The tool never writes the store key or the passphrase to a plain file.
- The key cache holds the store key and the SHA-256 of the `key.age` file it was unlocked from.
- If the cached store key cannot decrypt a file, the tool hashes the current `key.age`.
- If the hash differs from the cached hash, the tool asks for the passphrase and unlocks the new `key.age`.
- If the hash is equal, the tool stops with an error that names the file and says the store was changed outside envs.
- If `key.age` changes and the cached store key still decrypts the files, the tool updates the cached hash.

The hash rule lets other devices continue after `envs rotate`, and it separates a rotation from a tampered file.

### 8.5 Project link

- `envs init` writes `.envs.json` in the project root.
- The file contains the project name and no secret.
- The user commits this file to the project repository.
- The tool finds the file by a search from the current folder upward.
- The search stops at the first folder that contains an entry named `.git`, or at the filesystem root.
- If the search ends without a link file, the tool reports that no link file exists.
- If the project already exists in the store, `envs init` says so and asks for confirmation.

The `.git` boundary stops a downloaded repository inside a trusted project from inheriting the link file of that project.

### 8.6 Trusted folders

- The tool keeps a local list of trusted folders in `~/.envs/trusted.json`.
- Each entry holds an absolute folder path and a project name.
- The list is not synced.
- `envs init` adds the current folder to the list.
- Before a command uses a link file, the tool looks for the folder that contains the link file, and the project name, in the list.
- The tool resolves symlinks in the folder path before the comparison. On Windows, the comparison ignores case.
- If there is no match, the tool shows the folder and the project name and asks for confirmation.
- The confirmation defaults to no. Only the answer `yes` continues.
- If stdin is not a terminal, the tool stops with an error and does not ask.
- `--project` does not use the link file, so it needs no confirmation.

### 8.7 Sync

- The tool calls the system `git` binary, so it uses the existing git credentials of the user.
- The tool starts git directly with an argument list and never through a shell.
- The tool puts `--` before each URL or path argument.
- `envs login` accepts an `https` URL, an `ssh` URL, or a local path.
- `envs login` rejects a value that starts with `-` or that uses remote helper syntax (`<name>::`).
- `envs login` rejects an `https` URL that contains user information, because git would store it in plaintext.
- The tool removes `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `GIT_NAMESPACE`, and `GIT_PREFIX` from the environment of each git process.
- The tool sets `commit.gpgsign=false`, `user.name`, and `user.email` for each commit, so the git configuration of the user cannot block a commit.
- The first commit of a new store adds `.gitattributes` with `*.age binary`, so `core.autocrlf` cannot change ciphertext.
- Before each read, the tool runs a fetch with a timeout of 5 seconds, then a local fast-forward-only merge with no timeout.
- For that fetch, the tool disables terminal prompts, Git Credential Manager windows, and ssh prompts.
- A failed fetch and a non-fast-forward result both count as a failed sync.
- If the sync fails, `run` and `list` use the local clone and print a warning to stderr. For a non-fast-forward result, the warning says that the remote history changed.
- The flag `--offline` skips the sync.
- Each write follows this sequence: sync, decrypt, apply the change, encrypt, commit, push.
- If the remote rejects the push, the tool discards the local commit and repeats the sequence.
- If a file fails to decrypt inside the retry loop, the tool applies the 8.4 rules before the next attempt.
- The tool repeats the sequence a maximum of 3 times, then stops with an error.
- A write fails if the device is offline. The tool does not keep unpushed commits.
- Each commit message names the command, the project, the environment, and the key name.

### 8.8 Input

- `envs set` reads the value from a hidden prompt when stdin is a terminal.
- `envs set` reads the value from stdin when stdin is not a terminal.
- `envs set` removes one line ending, `\n` or `\r\n`, from the end of a stdin value.
- `envs set` rejects an empty value.
- `envs set` and `envs import` reject a value that contains a NUL byte, because an environment variable cannot hold it.
- `envs set` and `envs import` reject a key that differs only by case from a key in the same file, because Windows environment names ignore case.
- No command accepts a secret value as a command-line argument.
- `envs import` does not expand `$VAR` or `${VAR}`.
- `envs import` accepts `export KEY=value`, single and double quotes, `#` comments, and CRLF line endings.
- `envs import` rejects a key name that fails the 8.2 rule and names the line.
- `envs import` replaces the value of each key that exists and keeps all other keys.
- `envs import` makes one commit for the full file.
- `envs import` does not delete the source file.
- `envs import` prints a warning that the source file remains and that a deleted file is recoverable.

### 8.9 Run

- The child process gets the parent environment plus the stored values.
- A stored value overrides a parent variable with the same name.
- The tool passes stdin, stdout, and stderr through without change.
- The tool forwards interrupt signals to the child process.
- The tool exits with the exit code of the child process.
- On Windows, the tool must start `.cmd` and `.bat` shims such as `npx`.
- The tool does not start a program from the current folder unless the user gives an explicit path.

### 8.10 Login

- If the store contains secret files and no `key.age`, `envs login` stops with an error.
- The tool creates a store key only in an empty store.
- If the first push of a new store is rejected, the tool deletes the local clone and the key and tells the user to run `envs login` again. It does not retry with the same key.
- If `~/.envs/store` exists, `envs login` stops with an error that points to `envs logout`.
- If stdin is not a terminal, `envs login` stops with an error.
- The passphrase must have a minimum of 16 characters.
- On Unix, the tool creates `~/.envs` with mode `0700`.

### 8.11 Output and errors

- No command prints a secret value.
- `envs run` is the only way to use a stored value.
- Warnings and errors go to stderr.
- Each error message states the cause and the command that corrects it.
- The tool exits with a non-zero code on each failure.

## 9. Security

### 9.1 Threats and controls

| Threat | Control |
| --- | --- |
| A person reads the store repository, for example after a git host breach. | All values are encrypted. The store key is encrypted with scrypt and a passphrase of 16 characters or more. |
| A person with write access to the store adds a file with values of their choice. | Authenticated encryption (8.3). The tool rejects a file that the store key did not create. |
| A person with write access copies a file from one project to a different project. | The name check after decryption (8.3). |
| A person with write access deletes `key.age` to make a new device create a new key. | The login rule for a store without `key.age` (8.10). |
| A person with write access raises the scrypt work factor in a file header, or adds a very large file. | Work factor and size caps (8.3). |
| A person with write access corrupts a file to make the tool ask for the passphrase. | The `key.age` hash rule (8.4). The tool reports tampering instead of asking. |
| A person with write access rewrites the store history. | Fast-forward-only sync (8.7). The tool warns that the history changed. |
| A downloaded project contains a link file that names one of the user's projects. | Trusted folders (8.6). The tool asks before it injects values in an unknown folder. This guards against a mistake by the user, not against hostile code (9.2). |
| A downloaded repository inside a trusted project has no link file. | The `.git` boundary of the link file search (8.5). |
| A downloaded project contains a program with the same name as the dev command. | The tool does not start a program from the current folder (8.9). |
| A name or URL contains characters that change a file path or a git command. | Name rules (8.2) and git argument rules (8.7). |
| A value appears on screen, in scrollback, in logs, or in shell history. | No show command, hidden prompt, and no value arguments (8.8, 8.11). |
| A plaintext copy stays on disk. | The tool creates no plaintext file. `envs import` warns about the source file. |

### 9.2 Accepted risks

- Software that runs as the user can read the OS keychain, the process memory, and the environment of the child process.
- The child process and all its child processes get the values. Use `envs run` for the dev command only, not for `npm install`.
- The user holds the key, so `envs run -- printenv` shows the values. The lack of a show command prevents accidents only.
- The git host sees project names, environment names, and commit messages with key names.
- A person with the store repository can try passphrases offline with no limit. The passphrase strength is the only protection.
- A person with write access to the store can replace a file with an older version or delete files, with a new commit that keeps the history. Another clone or the git history restores them.
- A download that is not a git repository and sits inside a trusted project inherits the link file of that project.
- On Windows, `.cmd` and `.bat` programs run through `cmd.exe`, which expands `%NAME%` in the arguments against the injected environment.
- Hostile code that runs as the user can call `envs run --project <name>` with no confirmation.
- Go cannot erase a value from memory reliably. A swap file, a hibernation file, or a crash dump can contain values.
- Clipboard history and cloud clipboard sync can keep a pasted value.

### 9.3 Leak response

- `envs passwd` does not protect against a leaked passphrase. The old `key.age` stays in git history.
- `envs rotate` does not protect values that the old store key can decrypt from git history.
- After a leak of the passphrase or the store key, the user must do these steps in sequence:
  1. Change each secret at its provider.
  2. Run `envs passwd` and `envs rotate`.
  3. Store the new values with `envs set`.

## 10. Non-functional requirements

- `envs run --offline` adds less than 100 ms before the child process starts.
- `envs run` with a successful pull adds less than 1.5 s on a normal connection.
- The tool is one static binary for Windows, macOS, and Linux on amd64 and arm64.
- The tool needs git 2.30 or later on the `PATH`.
- The language is Go, version 1.25 or later. `filippo.io/age` v1.3.2 requires this version.

## 11. Cloudflare Workers use

1. Declare the secret names in `wrangler.jsonc`:
   ```jsonc
   { "secrets": { "required": ["API_KEY", "DB_PASSWORD"] } }
   ```
2. Do not create `.dev.vars` or `.env` in the project.
3. Start the dev server with `envs run -- npx wrangler dev`.

Wrangler loads the keys in `secrets.required` from the process environment.

## 12. Success criteria

- A new device is ready after `envs login` and one passphrase entry.
- No project on any device contains a `.dev.vars` or `.env` file with secret values.
- A value set on device A is available on device B on the next `envs run`.
- An accidental overwrite is recoverable from git history.
- Each threat in section 9.1 has an automated test that shows the control works.

## 13. Milestones

| Phase | Scope | Verification |
| --- | --- | --- |
| 1 | Store, encryption, key cache, trusted folders, and all phase 1 commands | Automated tests against a local bare git repository. Security tests for section 9.1. Manual test with two clones as two devices. |
| 2 | `passwd`, `rotate`, `log`, `logout` | Automated tests. Old passphrase fails and new passphrase works after `passwd`. A second clone continues after `rotate`. |
| 3 | Release binaries for all platforms | Install and run on Windows and one other OS. |

## 14. Decisions

- The name is `envs`. No command with this name exists on the development machine.
- Distribution is by release binaries only.
- The GitHub account `lminii` owns the repository.
  The Go module path is `github.com/lminii/envs`.

## 15. Pending decision

None.
