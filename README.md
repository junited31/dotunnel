# dotunnel

<p align="center"><img src="assets/dotunnel.png" alt="dotunnel: a hollow cylinder forming a tunnel" width="840"></p>

**English** | [한국어](README.ko.md)

`dotunnel` is a self-hosted stdio MCP server and helper for connecting a Linux
server to a private Secure MCP Tunnel. Its base API exposes seven bounded
workspace file/task tools. An operator may optionally configure agent
supervision for registered Herdr and/or tmux targets, adding eight shared
`agent_*` tools. It is not a hosted service or public MCP endpoint.

| Part | Includes |
|---|---|
| Core | Seven bounded workspace file/task MCP tools |
| Optional CLI jobs | Isolated jobs for separately installed Codex, Claude Code or OMP CLIs |
| Optional supervision | Eight shared `agent_*` tools for explicitly configured Herdr and/or tmux targets (15 tools total when enabled) |
| Optional runner | Separately installed [common JSON-stdio adapter runner](adapter_runner/README.md), which uses the seven base tools |

## Requirements

- Non-root Linux account; Python 3.11+ with `python3`, `venv` and `pip`.
- `curl` and `sha256sum` for the one-line installer; no `uv` required.
- ChatGPT/Platform eligibility and permissions, an OpenAI Tunnel ID and
  restricted runtime key, and the official `tunnel-client` are prepared
  separately. `dotunnel` cannot grant access or supply these.

## Install

Install the current release without a GitHub account:

```sh
curl -fsSL https://raw.githubusercontent.com/junited31/dotunnel/main/install.sh | sh
```

The installer verifies the pinned wheel before pip installs it in
`$HOME/.local/share/dotunnel/venv`, then exposes
`$HOME/.local/bin/dotunnel`. It does not run setup from piped stdin, install the
official client, or change accounts, permissions, keys, Tunnel settings, shell
startup or services. It refuses to overwrite an existing install or unrelated
launcher; use `dotunnel update` for an existing installation. If `dotunnel` is
not on `PATH`, add `$HOME/.local/bin` yourself or invoke it by absolute path.

Prefer downloading the wheel yourself? See [manual installation](docs/guide.md#manual-installation).

## Configure

Setup requires an interactive terminal. Separately install and
checksum-verify the official client; obtain the required account permissions,
Tunnel ID and Restricted runtime key. `dotunnel` cannot create these for you.

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

Setup creates a private profile/config/key outside a separate workspace, which
starts with `tasks: []`. Read the [detailed guide](docs/guide.md) for account
isolation, private installation and connecting the Tunnel to ChatGPT.

## Commands

| Command | Purpose |
|---|---|
| `dotunnel help` | Show usage |
| `dotunnel setup` | Create a Tunnel setup or configure optional CLI integrations |
| `dotunnel doctor` | Read-only configuration, client and connection diagnosis |
| `dotunnel update` | Check and interactively install a newer stable release |
| `dotunnel serve --config PATH` | Run the stdio MCP server with a trusted configuration |
| `dotunnel supervision init --config PATH` / `reinit` | Explicitly initialize or rotate optional supervision state |

## Optional Herdr/tmux agent supervision

Supervision is disabled unless the trusted configuration contains a fixed
`supervision` registry and its private state has been explicitly initialized.
The same eight shared `agent_*` tools are added whether one or both backends
are configured, for 15 MCP tools total. Fixed projects and profiles restrict
which registered connections can be used. Herdr sessions and tmux sockets may
coexist; the default connection chooses a new start only and never enables
broadcast or automatic fallback. See the [detailed guide](docs/guide.md#7-optional-herdrtmux-agent-supervision)
for approvals, handles, receipts and identity limits.

Available in [0.1.5](https://github.com/junited31/dotunnel/releases/tag/v0.1.5).
Installing the package does not configure or activate supervision.

## Optional common adapter runner

The [standalone runner](adapter_runner/README.md) uses the existing seven
file/task MCP tools. Install it separately from reviewed source and explicitly
register one fixed task; base installation and setup do not enable it.
Mutations require local interactive consent bound to the exact request and
private registry profile. Durable replay returns the recorded outcome without
redispatch; ambiguous effects remain `outcome_unknown`.

That runner ships no Herdr, Orca, tmux or provider adapters. Core supervision
is a separate feature; it supports configured Herdr/tmux backends, while Orca
support remains unavailable.

## Safety

- Run as a non-root account, preferably a dedicated account without broad groups
  or sudo. The project does not create accounts or change permissions.
- Keep the installed program, trusted configuration/credentials and writable
  workspace separate. Setup starts with `tasks: []` and stores credentials
  outside the workspace.
- Fixed tasks run with the MCP process account's full OS permissions. A fixed
  command or workspace is not a sandbox; review task code and side effects.
- stdio MCP has no separate user authentication. Restrict who can reach it;
  allowed files and task output may contain sensitive data.
- Optional CLI jobs require Bubblewrap. Their native CLI runs as the same user
  and may read its referenced credentials; allowlisted content can be sent to
  the provider. A candidate is not automatically applied or verified.
- `curl | sh` executes the repository's installer code as your user.
  Trust/review that script; the wheel checksum does not make the shell script
  itself a trust-free download.
- For source development, enable the [pre-commit secret guard](docs/guide.md#8-development-without-publishing-secrets); keep runtime/key files outside the checkout.

[Detailed guide](docs/guide.md) · [Design](DESIGN.md) ·
[Example config](config.example.json) · [License](LICENSE)
