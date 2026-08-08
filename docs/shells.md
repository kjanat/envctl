# Shell integration

Completion scripts and a PowerShell module, both generated at run time from the
same command and flag tables the parser validates against. They offer exactly
the flags each command accepts and cannot fall behind the binary.

## Completions

```sh
envctl completions bash
envctl completions zsh
envctl completions fish
envctl completions pwsh
```

`make install` writes the bash, zsh, and fish scripts under `$(PREFIX)`. To
install by hand, or to load without installing:

```sh
# bash
envctl completions bash > ~/.local/share/bash-completion/completions/envctl
source <(envctl completions bash)              # current shell only

# zsh, the directory must be in $fpath before compinit runs
envctl completions zsh > ~/.local/share/zsh/site-functions/_envctl
eval "$(envctl completions zsh)"               # current shell only, after compinit

# fish
envctl completions fish > ~/.config/fish/completions/envctl.fish
envctl completions fish | source               # current shell only
```

Under the default `PREFIX=~/.local`, zsh does not search
`~/.local/share/zsh/site-functions` on its own, so add it to `$fpath` before
`compinit` runs or the file sits there unused. `make install` prints a reminder
whenever `PREFIX` falls outside `/usr` and `/usr/local`.

fish reads both `~/.config/fish/completions` and the
`share/fish/vendor_completions.d` that `make install` writes. Either works;
installing to both just leaves two copies.

### What zsh gives you

Commands arrive grouped by what they do, and a usage line tracks where you are,
bolding what you have typed and underlining what comes next:

```
❯ envctl get <TAB>
envctl get [file] <KEY>
=== dotfile ===
.env  .env.local
=== file ===
prod.env  readme.md
=== directory ===
config/  scripts/

❯ envctl get .env.local <TAB>
envctl get [file] <KEY>
API_TOKEN  DATABASE_URL  DEBUG
```

The KEY position asks the binary for that file's keys instead of offering
filenames, and picks the right set per command: `enable` offers the disabled
keys, `set` and `delete` all of them, `get --env` the environment. A file with
no keys says so rather than completing nothing.

### PowerShell

```powershell
envctl completions pwsh | Out-String | Invoke-Expression   # current session
envctl completions pwsh >> $PROFILE                        # persistent
```

Completions carry tooltips, shown by `MenuComplete` (Ctrl+Space) and in
Predictive IntelliSense list view. The
[CompletionPredictor](https://www.powershellgallery.com/packages/CompletionPredictor)
module surfaces anything tab-completable, these completions included, as
predictions while you type (PowerShell 7.2+):

```powershell
Install-PSResource -Name PSReadLine, CompletionPredictor
# in $PROFILE:
Import-Module CompletionPredictor
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
```

F2 toggles between the inline and list prediction views.

## PowerShell cmdlets

`envctl module pwsh` writes a module that wraps the binary in cmdlets whose
output is objects, so results compose with the pipeline instead of string
matching:

```powershell
envctl module pwsh | Out-String | Invoke-Expression   # current session, or in $PROFILE
envctl module pwsh > envctl.psm1                      # Import-Module ./envctl.psm1

Get-EnvctlKey -File .env | Where-Object Key -like '*TOKEN*'
Get-EnvctlEnvironment | Where-Object Redacted
Set-EnvctlValue -Key DEBUG -Value true -WhatIf
npm run build 2>&1 | Invoke-EnvctlRedact -Environment
```

| Cmdlet                  | Wraps            |
| ----------------------- | ---------------- |
| `Get-EnvctlValue`       | `envctl get`     |
| `Set-EnvctlValue`       | `envctl set`     |
| `Disable-EnvctlKey`     | `envctl disable` |
| `Enable-EnvctlKey`      | `envctl enable`  |
| `Remove-EnvctlKey`      | `envctl delete`  |
| `Get-EnvctlKey`         | `envctl list`    |
| `Get-EnvctlEnvironment` | `envctl env`     |
| `Invoke-EnvctlRedact`   | `envctl redact`  |

Objects carry `Key`, `Value`, `Redacted`, and `RedactionKind` (`private-key` or
`credentials` for the typed tokens, `$null` otherwise). `Get-EnvctlKey` adds
`Disabled` and `File`, so a pipeline over several files keeps track of where
each key came from.

The mutating cmdlets support `-WhatIf` by running the underlying command with
`--dry-run`, so the preview is the real diff. A missing key becomes an
`ErrorRecord` that respects `-ErrorAction` and `-ErrorVariable`. `Get-Help`
serves the same synopsis, description, and parameter text as the man page, with
an example per cmdlet.

The binary must be on `PATH` as `envctl`.
