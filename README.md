# fishbowl

Isolated, fully audited security-research environments on macOS.

Each session is one lightweight virtual machine started through
[`apple/container`](https://github.com/apple/container). Inside it: a Kali headless
toolchain for analysing samples. Outside it: your credentials, which never cross the
boundary.

You never start, stop, list or delete a machine. You open a session; the machine under it
is created when you need one, resumed when you come back to it, and reclaimed once it has
gone a week untouched, the host runs short of disk, or the store the sessions live in
outgrows its allowance.

## What it guarantees

**A sample never reaches a credential.** Codex leaves its login on the host entirely.
Claude Code runs inside the session and is lent an access token that expires in hours,
written to a file only the researcher account can open and taken away the moment the agent
exits; the refresh token behind it never crosses. Devin's login is a credentials file with
no short-lived part to lend instead, so the file itself crosses on the same terms —
present only while the agent runs. Samples are detonated under a third account no
credential is ever written for, so a sample that reads every file it can reach still finds
none.

**Every connection, datagram and DNS question crosses the gateway — both address
families of them; how much is inspected is your call.** Apart from the detonation
account's — whose traffic is cut
entirely — traffic is redirected by uid to an in-guest gateway, and the session's audit
tier (`--audit`), settled when the session is created, says what it does with it:

- `strict` terminates TLS with its own authority and records every DNS question,
  connection, TLS handshake and HTTP exchange as JSONL. Anything the gateway cannot
  audit — QUIC above all — is dropped by the packet filter rather than passed.
- `default` audits without standing in the connection's way: TLS client hellos are read
  for their SNI and relayed end-to-end untouched, plaintext HTTP is parsed where it
  already is plaintext, and traffic no permitted egress route can carry is refused
  immediately rather than dropped into a timeout.
- `off` relays everything and records nothing about it. The egress layer's own route
  reports still land on the trail — they carry no user traffic, and they are the
  host's proof that a strict egress mode is really being enforced.

The policy is installed by the init process before anything else runs, and
`CAP_NET_ADMIN` is removed from the bounding set afterwards, so code inside the
sandbox cannot change it even as root. If the gateway dies, the redirect target stops
listening and egress fails closed.

**The route out is yours.** Audited traffic leaves the machine over an egress transport
chosen when the session is opened (`--egress`): `auto`, the default, tunnels through
Cloudflare WARP when a tunnel can be raised and falls back to the machine's own address
when it cannot; `warp` and `tor` are strict — while their transport is down,
connections are refused rather than sent out under your address — and `direct` asks
for no tunnel at all. Both transports live inside the gateway's own process — a
userspace WireGuard session for WARP, an Arti client for Tor — so the packet filter
never changes, and every transition between routes is itself written to the audit
trail. DNS crosses the same route, and where a route can carry datagrams the relay
moves the rest of UDP — QUIC included — across it transparently; where it cannot
(Tor carries none, and `strict` keeps QUIC off an unauditable transport) a
datagram is refused outright. Destinations no exit could ever reach — the
machine's own network, private and local address space — always go direct,
whatever the mode.

**Red team mode.** `--redteam` opens a session for an engagement you are authorized
for. Before anything is started, the terminal asks you to attest that authorization —
anything but an explicit yes ends the opening, and the attestation is asked again on
every later opening of the session. Inside, the agent is briefed that the engagement
is authorized and tasked to operate offensively. The session's base egress is the WARP
tunnel — strict, so the machine's own address is never an exit — and Tor rides beside
it as a per-command leg rather than as the floor: run a target-bound command through
`torsion` (`torsion nmap -sV target`) and its TCP and DNS are carried over Tor,
refused while Tor is down and its UDP refused always — Tor transports no
datagrams — while the agent's own tooling and control traffic stay on the fast
path. The audit trail still sees everything, including which leg each record
rode.

## Install

```sh
cargo install fishbowl
```

Tagged `fishbowl-v*` releases also ship a prebuilt aarch64-apple-darwin binary and a
`fishbowl-installer.sh` for systems without a Rust toolchain.

fishbowl carries its own runtime: on first use it fetches Apple's signed
[`container`](https://github.com/apple/container) release — a version this build pins
by digest — into `~/.fishbowl/toolchain`, and starts its services itself. Nothing
needs to be installed first; everything after — the Kali image, the auditing gateway —
is pulled, not built.

## Use

```sh
fishbowl shell  --samples ~/samples  # a new session, with samples mounted read-only
fishbowl claude --samples ~/samples  # the same, with Claude Code driving it
fishbowl codex  --samples ~/samples  # or Codex
fishbowl devin  --samples ~/samples  # or Devin
fishbowl audit c0ffee                # follow every packet that session sends
fishbowl shell --resume              # pick a session to come back to
fishbowl claude --resume c0ffee      # or name it
```

The first run pulls the Kali image — with the gateway compiled into it — from
`ghcr.io/lexoliu/fishbowl`, where CI builds it per architecture for every merge and
tags it with the tool's version for every release. Nothing is compiled on your machine.
The image a checkout would build is named for the digest of its sources, so an image CI
already pushed under that name is pulled rather than rebuilt; upgrading fishbowl
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

The researcher account has passwordless `sudo` — the machine is disposable and the
boundary is around it, not inside it, so kernel debugging and system changes are yours.
What root still cannot touch is the packet filter: `CAP_NET_ADMIN` is dropped from the
bounding set before `sshd` starts, so no process inside can alter egress. The
`detonate` account alone is given no `sudo` rule, so a sample never finds a way out of
its uid.

A detonated sample has no network. The machine is virtualized rather than
network-isolated, so traffic a sample sent under the researcher's uid would reach the
real internet — the packet filter therefore drops everything the detonation account
emits, loopback aside. A C2 that only ever receives a connection attempt that goes
nowhere is exactly what running the thing was for.

This is a second uid inside a machine that is itself the boundary. If an agent running
unattended is talked into running a sample under its own account, the separation is gone
and the loss is the token it was lent for those hours — the virtual machine still holds.

## Your own keys

A MalwareBazaar key on the host is handed to the session. Export it as
`MALWAREBAZAAR_API_KEY` — or `MALWAREBAZAAR_AUTH_KEY`, after the `Auth-Key` header it is
sent as — and every session you open afterwards has the key as `MALWAREBAZAAR_API_KEY` in
the researcher account's environment; leave both unset and nothing is passed. There is no
flag and no setting, because the variable is the switch. The summary printed when a
session opens says which it was.

The value travels in ssh's own environment forwarding, by name, so it never appears on a
command line, and the session's sshd accepts that one name and no other. Samples never see
it: they run as a separate account, and `sudo` resets the environment on the way there.
Claude Code, Codex and Devin are told the key exists and what it is for when they start,
so you do not have to.

`--arch amd64` runs an x86_64 root filesystem under Rosetta, for samples that are not
arm64. It is settled when the session is created, so an `amd64` sample gets its own
session rather than a flag on an existing one.

## Agents

`fishbowl claude`, `fishbowl codex` and `fishbowl devin` open a session
and hand it to an agent running with approvals off: the session is the sandbox, so an
agent that stops to ask for permission to read a file is one you have to babysit for no
gain.

All three keep your subscription. None is given anything that could be used to log in as
you after the run.

### Claude Code

Claude Code runs inside the session, because that is where the sample is. What stays on
the host is the login: fishbowl reads the access token out of your Keychain, serves
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
about a directory fishbowl made seconds earlier.

Codex's hooks are switched off for the run, with a command-line override rather than a
change to your settings. Hooks are the one part of Codex that executes on the host, and the
ones a stock install carries belong to plugins that drive your browser; Codex remembers its
trust in them per directory, so left on they would stop every session's first prompt with a
review of hooks that have nothing to do with the session.

That directory is `~/.fishbowl/work/<id>`, and on the host it stays empty. Codex
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
| `fishbowl` | The CLI |
| `fishbowl-runtime` | Typed driver for the `container` CLI, and the fetcher that lays its pinned toolchain down |
| `fishbowl-image` | Renders the Dockerfile, entrypoint and egress policy; stages the build context |
| `fishbowl-gateway` | The in-guest auditing proxy (Linux only) |
| `fishbowl-courier` | Holds an agent's borrowed credential in-guest (Linux only) |
| `fishbowl-creds` | The borrowed credential's wire and on-disk formats |
| `fishbowl-audit` | Audit record schema and JSONL reader/writer |
| `fishbowl-egress` | The transports a session's audited egress rides on: WARP, Tor, or direct |
| `fishbowl-agents` | Reads the host's logins and registers a session with Codex |

## Install

```sh
FISHBOWL_SIGNING_IDENTITY="Apple Development: You (TEAMID)" scripts/install.sh
```

The script builds the release binary, signs it with a certificate of yours, and installs it
into `~/.local/bin`. `security find-identity -v -p codesigning` lists the certificates you
have; an Apple Development certificate is enough.

The signature is what stops macOS asking for your password. `fishbowl claude` reads
your Claude Code login from the Keychain, and the Keychain only lets an application do that
silently once you have answered **Always Allow** for it — an answer it remembers by the
application's signed identity. A binary straight out of `cargo build` carries only the
linker's ad-hoc signature, a new identity on every build, so every rebuild asks again.
Signed the same way each time, you answer once.

## Requirements

macOS 26 on Apple silicon, and nothing else: the `container` toolchain is fetched on
first run. `FISHBOWL_CONTAINER` can point at a `container` binary to drive instead of
the managed one — for trying an upstream build, say — and is otherwise left unset.

## License

Apache-2.0
