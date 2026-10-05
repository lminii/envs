# Security review of PRD.md

Date: 2026-10-05
Reviewed document: `PRD.md`, status Final, dated 2026-10-05.

## Method

The review walks each requirement in sections 6 to 10 against the threat table in section 9.1.
It checks the external facts the PRD relies on against the sources: `filippo.io/age` v1.3.2 (`scrypt.go`), `github.com/zalando/go-keyring` v0.2.8 (`keyring_darwin.go`, `keyring_windows.go`, `keyring_mock.go`), Go 1.25 `os/exec`, and `github.com/joho/godotenv` (`parser.go`).

## Verdict

The core design is sound.
A random 256-bit store key, age scrypt mode as an authenticated wrapper, the key in the OS keychain, and no plaintext on disk give the properties the PRD claims.
No finding below gives an attacker a secret value.
The findings are missing controls for availability and integrity, and gaps in the spec that an implementation can get wrong.

## Verified claims

- age scrypt mode is authenticated (8.3). The file key is wrapped with ChaCha20-Poly1305 under the scrypt-derived key, the header carries an HMAC, and the payload uses STREAM with a last-chunk flag that detects truncation. A party without the store key cannot produce a file that decrypts.
- `ScryptIdentity` rejects a file with any non-scrypt stanza, so an attacker cannot add a second recipient.
- go-keyring on macOS writes the secret to `security -i` over stdin, so it does not appear in `ps` output. On Windows the credential blob limit is 2560 bytes. The store key needs 64.
- Go `os/exec` returns `ErrDot` for a program found only in the current folder since Go 1.19, on every platform (8.9). It also rejects an environment that contains a NUL byte.
- `filippo.io/age` v1.3.2 declares `go 1.25.0`, so the Go 1.25 requirement in section 10 is correct. The current Go release is 1.27.1. This machine has go1.24.5. The `go` command downloads the newer toolchain on demand, but install a current release before the first build.

## Findings

Severity.
Medium: a person with write access to the store can deny service or hide tampering.
Low: a spec gap that causes wrong behavior or a weaker control.
Info: a fact to document.

Status.
The owner accepted all ten findings on 2026-10-05.
`PRD.md` contains the changes.
The optional version counter in F2 was declined, because git history already shows a same-history replay and the field adds format complexity.

### F1. Scrypt work factor is not capped on read

Severity: Medium. Sections 8.3 and 9.1.
Status: Accepted.

age stores the scrypt work factor in the file header.
`ScryptIdentity` accepts any work factor up to 2^22 by default, which costs about 4 GiB of memory and 15 seconds on a modern machine.
The MAC that detects a forged file is checked after scrypt runs.
A person with write access can therefore edit the header of `key.age` or of any secret file.
Every `envs run`, `envs list`, or `envs login` on every device then spends seconds and gigabytes per file.
The "low work factor" in 8.3 applies to writing. It does nothing on the read side without a cap.

Change:
- 8.3: "The tool rejects a secret file whose scrypt work factor is above the value the tool writes. The tool rejects `key.age` with a work factor above 2^20. The tool rejects an `.age` file larger than 1 MiB before it parses the file."
- 9.1: add the row "A person with write access raises the scrypt work factor in a file header, or adds a very large file. | Work factor and size caps (8.3)."

### F2. `git pull` under a kill timeout, and no fast-forward check

Severity: Medium. Section 8.7.
Status: Accepted, without the optional version counter.

`git pull` is a fetch followed by a merge that writes the index and the working tree.
A 5 second timeout that kills git during the merge step can leave the clone in a merging state with lock files.
Every later command then fails until the user repairs the clone by hand.
A kill during a fetch leaves only unreferenced objects.

The design keeps the local clone equal to the remote, because the tool never keeps unpushed commits.
So a non-fast-forward result after a fetch has one cause: the remote history was rewritten.
That is a cheap tamper signal, and the PRD does not use it.
Section 9.2 accepts that a person with write access can restore an old version of a file.
A rewritten history is the simplest way to do that, and this change detects it.

Change:
- 8.7: "Before each read, the tool runs `git fetch` with a timeout of 5 seconds, then a local fast-forward-only merge with no timeout. A failed fetch and a non-fast-forward result both count as a failed sync. The warning for a non-fast-forward result says that the remote history changed."
- Optional: add a `version` counter to the JSON in 8.1 that increases on each write. The tool compares it with the previous local copy and warns when it goes down. This also detects a replay that keeps the history intact.

### F3. A tampered file triggers a passphrase prompt, and rotation looks like tampering

Severity: Medium. Sections 8.4, 7 (`rotate`), and 8.7.
Status: Accepted.

Rule 8.4 says: when the cached store key cannot decrypt a file, read `key.age` again and ask for the passphrase.
A person with write access who corrupts one secret file causes a passphrase prompt on every device at the next read.
The prompt is identical to the one after `envs rotate`.
The typed passphrase does not leave the machine, so this is not a leak.
It is a detection failure: tampering looks like routine rotation, and the user learns to type the passphrase whenever asked.

Change:
- 8.4: "The key cache stores the store key and the SHA-256 of the `key.age` file it was unlocked from. When a file fails to decrypt, the tool hashes the current `key.age`. If the hash differs, the tool asks for the passphrase. If the hash is equal, the tool stops with an error that names the file and says the store was changed outside envs. When `key.age` changes and the cached key still decrypts files, the tool updates the stored hash."
- 7 or 8: "`envs rotate` writes the new `key.age` and every re-encrypted file in one commit."
- 8.7: "If a file fails to decrypt inside the write retry loop, the tool applies the 8.4 rule before the next attempt."

### F4. The trusted-folder check does not say which folder, and a nested download inherits a trusted link

Severity: Low. Sections 8.5 and 8.6.
Status: Accepted.

Clarity.
Rule 8.6 adds "the current folder" at `envs init` and later looks for "the folder".
With the upward search in 8.5, the current folder and the folder of the link file differ in every subfolder.
An implementation that checks the current folder prompts in every subfolder.
An implementation that compares raw path strings prompts again after a symlink or a case difference on Windows.
No bypass follows from this, but the spec should name the folder: the one that contains the link file, after symlink resolution, compared without case on Windows.

Gap.
The upward search crosses repository boundaries.
When the user clones or unpacks a downloaded project inside a trusted project, for example `myapp/tmp/evil`, the download needs no link file.
The search finds `myapp/.envs.json`, that folder is trusted, and `envs run` injects the secrets of `myapp` into the downloaded code with no prompt.
The 9.1 row covers only a link file inside the download.

Change:
- 8.5: "The search stops at the first folder that contains an entry named `.git`. If that folder has no link file, the tool reports that no link file exists."
- 8.6: "The check uses the folder that contains the link file, after symlink resolution. On Windows the comparison ignores case. The prompt defaults to no and continues only on the answer `yes`."
- 9.2: "A download that is not a git repository and sits inside a trusted project inherits the link file of that project."

### F5. Git environment and configuration inheritance

Severity: Low. Section 8.7.
Status: Accepted.

- Git sets `GIT_DIR`, `GIT_WORK_TREE`, and `GIT_INDEX_FILE` while it runs hooks, and some tools set them too. If `envs run -- npm test` runs inside a pre-commit hook, the git commands of the tool act on the project repository instead of the store. The tool must remove these variables, plus `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `GIT_NAMESPACE`, and `GIT_PREFIX`, from the environment of every git process.
- The git configuration of the user applies to the store. `commit.gpgsign=true` makes each commit prompt for a key or fail. A missing `user.email` makes commits fail. `core.autocrlf=true` rewrites files that git classifies as text, and an age file starts with a text header. The tool should pass `-c commit.gpgsign=false -c user.name=envs -c user.email=envs@localhost` and add `.gitattributes` with `*.age binary` in the first commit.
- "Git credential prompts are disabled" needs three settings. `GIT_TERMINAL_PROMPT=0` stops terminal prompts. Git Credential Manager opens a window unless `GCM_INTERACTIVE=never`. ssh asks for host keys and key passphrases unless `BatchMode=yes`.

Change: add these to 8.7.

### F6. Environment variable edge cases

Severity: Low. Sections 8.8 and 8.9.
Status: Accepted.

- A value with a NUL byte cannot be an environment variable. Go rejects the whole environment at `envs run` with the message "environment variable contains NUL", after the value was already encrypted and pushed. `envs set` and `envs import` must reject it.
- Windows environment variable names ignore case. `Api_Key` and `API_KEY` are two JSON keys but one variable, and the last one wins. The tool should reject a key that differs only by case from an existing key in the same file.
- "Removes one line ending" must cover `\r\n`. PowerShell adds `\r\n` to piped text. Windows PowerShell 5.1 also re-encodes piped text and can change non-ASCII bytes. The hidden prompt is the safe path for such values.

Change: add these to 8.8.

### F7. Dotenv parsing is unspecified

Severity: Low. Section 8.8.
Status: Accepted.

Dotenv has no standard.
Common parsers, `github.com/joho/godotenv` among them, expand `$VAR` and `${VAR}` inside unquoted and double-quoted values.
Secrets often contain `$`.
An import that expands variables changes a secret in silence.

Change: 8.8: "`envs import` does not expand variables. It accepts `export KEY=value`, single and double quotes, `#` comments, and CRLF line endings. It rejects a key name that fails the 8.2 rule and names the line."

### F8. Login edge cases

Severity: Low. Sections 6.1 and 8.10.
Status: Accepted.

- Two devices run `envs login` against an empty store at the same time. Both create a key, and the second push is rejected. The tool must not retry with its own key. It must discard the clone and the key and tell the user to run `envs login` again.
- `envs login` while `~/.envs/store` exists is undefined. The tool should refuse and point to `envs logout`.
- `envs login` when stdin is not a terminal is undefined. The passphrase prompt has no non-interactive path, so the tool should stop with an error, as 8.6 does.

Change: add these to 8.10.

### F9. Windows batch shims run through cmd.exe

Severity: Info. Sections 8.9 and 9.2.
Status: Accepted.

Windows runs `.cmd` and `.bat` files through `cmd.exe`, and Go documents that `cmd.exe` parses the command line with different quoting rules.
The arguments of `envs run` come from the user, so this is not an injection path in the 9.1 model.
But `cmd.exe` expands `%NAME%` tokens in the command line against the child environment, which now contains the secrets.
`envs run -- npx foo %API_KEY%` therefore passes the secret as a visible argument.

Change: add to 9.2: "On Windows, `.cmd` and `.bat` programs run through `cmd.exe`, which expands `%NAME%` in the arguments against the injected environment."
Implementation rule: never add `cmd /c`. `exec.LookPath` and `ErrDot` already satisfy 8.9.

### F10. URL with embedded credentials

Severity: Low. Section 8.7.
Status: Accepted.

`envs login https://user:token@host/owner/store.git` stores the token in plaintext in `~/.envs/store/.git/config`.
The tool should reject an https URL with user information and tell the user to use the git credential helper.

Change: add to 8.7.

## Notes on accepted risks

- The trusted-folder control (8.6) guards against the mistake of the user, not against hostile code. Hostile code that already runs as the user can call `envs run --project <name>` with no prompt, read the keychain, or read the store. This is consistent with 9.2, but the 9.1 row should say so, so the control is not read as a defense against hostile code.
- The non-goal "no production secrets" has no enforcement. `--env prod` works like any other name. This is a policy, not a control.
