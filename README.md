# cyber-sandbox

Isolated, fully audited security-research environments on macOS.

Each session is one lightweight virtual machine started through
[`apple/container`](https://github.com/apple/container). Inside it: a Kali headless
toolchain for analysing samples. Outside it: your credentials, which never cross the
boundary.

You never start, stop, list or delete a machine. You open a session; the machine under it
is created when you need one, resumed when you come back to it, and reclaimed once it has
gone a week untouched or the host runs short of disk.

## What it guarantees

**A sample never reaches a credential.** Codex leaves its login on the host entirely.
Claude Code runs inside the session and is lent an access token that expires in hours,
written to a file only the researcher account can open and taken away the moment the agent
exits; the refresh token behind it never crosses. Devin's login is a credentials file with
no short-lived part to lend instead, so the file itself crosses on the same terms —
present only while the agent runs. Samples are detonated under a third account no
credential is ever written for, so a sample that reads every file it can reach still finds
none.

**No packet leaves unaudited.** Traffic is redirected by uid to an in-guest gateway that
terminates TLS with its own authority and records every DNS question, connection, TLS
handshake and HTTP exchange as JSONL. Anything the gateway cannot audit — QUIC above all
— is dropped by the packet filter rather than passed. The policy is installed by the init
process before anything else runs, and `CAP_NET_ADMIN` is removed from the bounding set
afterwards, so code inside the sandbox cannot change it even as root. If the gateway
dies, the redirect target stops listening and egress fails closed.

## Use

```sh
cyber-sandbox shell  --samples ~/samples  # a new session, with samples mounted read-only
cyber-sandbox claude --samples ~/samples  # the same, with Claude Code driving it
cyber-sandbox codex  --samples ~/samples  # or Codex
cyber-sandbox devin  --samples ~/samples  # or Devin
cyber-sandbox audit c0ffee                # follow every packet that session sends
cyber-sandbox shell --resume              # pick a session to come back to
cyber-sandbox claude --resume c0ffee      # or name it
```

The first run pulls the Kali image — with the gateway compiled into it — from
`ghcr.io/lexoliu/cyber-sandbox`, where CI builds it per architecture for every merge and
tags it with the tool's version for every release. Nothing is compiled on your machine.
The image a checkout would build is named for the digest of its sources, so an image CI
already pushed under that name is pulled rather than rebuilt; upgrading cyber-sandbox
replaces the image on the next new session and an unchanged one never does. A session
keeps the image it was created from, and images no session refers to are removed on the
way in to the next one.

Run from a checkout — or point `--workspace` at one — and the sources there are what the
guest is compiled from: the image is built locally only when the registry does not
already hold exactly that digest.

## Detonating a sample

Inside a session, run a sample through `detonate`:

```sh
detonate ./suspicious-binary
detonate python3 unpack.py /samples/dropper.xls
```

The researcher account is the one the shell and both agents run as, and the one an agent's
borrowed token is written for. `detonate` runs its argument as a separate account instead,
which owns nothing, is not the owner of the credential file, and cannot read the directory
the credential is written into. `sudo` resets the environment on the way through, so the
token an agent holds does not travel into a sample the agent starts. The working directory
is shared between the two accounts, because that is where the sample and what it leaves
behind both belong.

This is a second uid inside a machine that is itself the boundary. If an agent running
unattended is talked into running a sample under its own account, the separation is gone
and the loss is the token it was lent for those hours — the virtual machine still holds.

## Your own keys

A MalwareBazaar key on the host is handed to the session. Export it as
`MALWAREBAZAAR_API_KEY` and every session you open afterwards has the same variable in the
researcher account's environment; leave it unset and nothing is passed. There is no flag
and no setting, because the variable is the switch. The summary printed when a session
opens says which it was.

The value travels in ssh's own environment forwarding, by name, so it never appears on a
command line, and the session's sshd accepts that one name and no other. Samples never see
it: they run as a separate account, and `sudo` resets the environment on the way there.
Claude Code, Codex and Devin are told the key exists and what it is for when they start,
so you do not have to.

`--arch amd64` runs an x86_64 root filesystem under Rosetta, for samples that are not
arm64. It is settled when the session is created, so an `amd64` sample gets its own
session rather than a flag on an existing one.

## Agents

`cyber-sandbox claude`, `cyber-sandbox codex` and `cyber-sandbox devin` open a session
and hand it to an agent running with approvals off: the session is the sandbox, so an
agent that stops to ask for permission to read a file is one you have to babysit for no
gain.

All three keep your subscription. None is given anything that could be used to log in as
you after the run.

### Claude Code

Claude Code runs inside the session, because that is where the sample is. What stays on
the host is the login: cyber-sandbox reads the access token out of your Keychain, serves
it over a unix socket, and forwards that socket into the session over ssh. Inside, a
courier fetches the token, writes it where Claude Code looks for a host-managed
credential, starts Claude Code, and fetches again every five minutes so a token renewed on
the host reaches the session without the session ever holding what renews it.

The refresh token never crosses. What the session gets is the access token, which expires
in hours on its own, is readable only by the account the agent runs as, and is taken off
the disk when the agent exits. Even a copy taken while the agent ran is inert afterwards:
Claude Code checks that the process the credential names is still alive and was started
when the file says it was.

Your own `claude` is untouched — the Keychain item is read, never rewritten, so nothing
here can make you log in again.

### Codex

Codex itself never leaves the host. Your ChatGPT subscription, and the credential behind
it, stay where they already are; what runs in the session is `codex exec-server`, which
authenticates to nothing.

Three things in your configuration are borrowed for the length of a run and handed back
exactly as they were: the session becomes an entry in `~/.codex/environments.toml`, it is
preselected there so Codex opens on it without a menu, and the directory it works in is
marked trusted in `~/.codex/config.toml` so opening it does not begin with a question
about a directory cyber-sandbox made seconds earlier.

Codex's hooks are switched off for the run, with a command-line override rather than a
change to your settings. Hooks are the one part of Codex that executes on the host, and the
ones a stock install carries belong to plugins that drive your browser; Codex remembers its
trust in them per directory, so left on they would stop every session's first prompt with a
review of hooks that have nothing to do with the session.

That directory is `~/.cyber-sandbox/work/<id>`, and on the host it stays empty. Codex
resolves the directory it works in against the host and then asks the session to execute
there, so the path has to exist on both sides — inside the session the same path is a
symlink to `/work`. Nothing is mounted through it, and a session left holding a path the
host does not have is one where Codex quietly runs the command on your laptop instead.

### Devin

Devin runs inside the session for the same reason Claude Code does: it is one program,
with no tool side to leave on the host. What it is lent is different. Devin's login is
`~/.local/share/devin/credentials.toml` — a session key plus the endpoints it
authenticates to, with no expiring token to lend in its place — so the file itself
crosses the socket, is written where Devin reads it, and is taken off the disk when Devin
exits.

The key does not expire on its own the way an OAuth token does, so the loan's bound is
the run rather than a clock. The host re-reads the file every time the courier asks, so
logging in again on the host reaches a running session; the socket stops existing when
the run does, so nothing can fetch it afterwards; and the file in the session is readable
only by the researcher account for as long as it exists at all. Your own `devin` is
untouched — its credentials file is read, never written.

## Layout

| Crate | Role |
|---|---|
| `cyber-sandbox` | The CLI |
| `cyber-sandbox-runtime` | Typed driver for the `container` CLI |
| `cyber-sandbox-image` | Renders the Dockerfile, entrypoint and egress policy; stages the build context |
| `cyber-sandbox-gateway` | The in-guest auditing proxy (Linux only) |
| `cyber-sandbox-courier` | Holds an agent's borrowed credential in-guest (Linux only) |
| `cyber-sandbox-creds` | The borrowed credential's wire and on-disk formats |
| `cyber-sandbox-audit` | Audit record schema and JSONL reader/writer |
| `cyber-sandbox-agents` | Reads the host's logins and registers a session with Codex |

## Install

```sh
CYBER_SANDBOX_SIGNING_IDENTITY="Apple Development: You (TEAMID)" scripts/install.sh
```

The script builds the release binary, signs it with a certificate of yours, and installs it
into `~/.local/bin`. `security find-identity -v -p codesigning` lists the certificates you
have; an Apple Development certificate is enough.

The signature is what stops macOS asking for your password. `cyber-sandbox claude` reads
your Claude Code login from the Keychain, and the Keychain only lets an application do that
silently once you have answered **Always Allow** for it — an answer it remembers by the
application's signed identity. A binary straight out of `cargo build` carries only the
linker's ad-hoc signature, a new identity on every build, so every rebuild asks again.
Signed the same way each time, you answer once.

## Requirements

macOS 26 on Apple silicon, and `brew install container`.

## License

Apache-2.0
