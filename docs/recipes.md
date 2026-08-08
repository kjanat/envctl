# Recipes

Tasks people actually reach for envctl to do.

## Read a key in a script

```sh
DATABASE_URL=$(envctl get .env DATABASE_URL) || exit 1
```

`get` writes the raw value to a pipe, so command substitution keeps working.
Exit 1 means the key has no active definition, which is worth checking rather
than carrying an empty string forward.

## Flip a feature flag safely

```sh
envctl --dry-run set .env FEATURE_X true   # look first
envctl set .env FEATURE_X true             # then do it
```

The dry run prints the exact diff and writes nothing.

## Keep a value while turning it off

```sh
envctl disable .env DEBUG   # becomes #DEBUG=verbose
envctl enable .env DEBUG    # back, same value
```

Better than deleting and retyping, since the value stays in the file where you
can still read it.

## Rotate a secret

```sh
envctl --dry-run set .env API_TOKEN "$new"   # confirm the target
envctl set .env API_TOKEN "$new"
envctl --redact get .env API_TOKEN           # confirm without printing it
```

The value is literal, so no quoting rules inside it can bite you.

## Mask secrets in tool output

```sh
npm run build 2>&1 | envctl redact
terraform apply 2>&1 | envctl redact prod.env
kubectl describe pod api 2>&1 | envctl redact --env
```

The env file supplies literal values to match, on top of the shape heuristics.
`--env` uses the process environment instead, which is what you want when the
secrets came from the environment rather than a file.

## Show your environment to someone

```sh
envctl env             # instead of env
envctl env --sort      # alphabetical
```

Always redacted, one entry per line, control bytes escaped. A `LESS_TERMCAP_*`
value cannot restyle the terminal and a value containing a newline cannot forge
extra entries.

## Read an encrypted env file without decrypting to disk

```sh
envctl redact <(sops -d secrets.env)
envctl get <(sops -d secrets.env) DATABASE_URL
```

Read commands accept any openable path, so process substitution works.

## Audit which keys look secret

```sh
envctl --redact list .env --values
```

Anything printed as `<redacted>` matched a rule. Anything printed in full did
not, which is the useful direction to read it in when you are checking coverage
before sharing a file.

## Catch high-entropy values under innocent names

```sh
envctl --paranoid list .env --values
```

`--paranoid` applies the entropy bar regardless of key name, so
`RANDOM_THING=<44 random chars>` gets masked too. Trivial values, plain paths,
and digest-like names stay visible.

## Compare two env files

```sh
diff <(envctl --redact list a.env --values --sort) \
     <(envctl --redact list b.env --values --sort)
```

`--sort` puts both sides in key order, and `--redact` keeps the secrets out of
the diff while still showing which keys differ.

## Find keys that are commented out

```sh
envctl list .env --all | grep '(disabled)'
```

## Use it from PowerShell

```powershell
Get-EnvctlKey -File .env | Where-Object Disabled
Get-EnvctlEnvironment | Where-Object Redacted | Select-Object Key
```

See [shells.md](shells.md) for loading the module.

## Let a coding agent read your files

Agents that inherit a TTY get redaction automatically, and there is nothing to
configure. To make it explicit in a prompt or a tool definition:

```sh
envctl --redact list .env --values   # never prints a real secret
envctl redact < .env                 # same, for the whole file
```

Both are safe to put in front of a model. `--raw` is the escape hatch when a
human genuinely needs the value.
