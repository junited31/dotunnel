# dotunnel

<p align="center"><img src="assets/dotunnel.png" alt="dotunnel: a hollow cylinder forming a tunnel" width="840"></p>

**English** | [한국어](README.ko.md)

`dotunnel` is a self-hosted stdio MCP server and helper for connecting a Linux
server to a private Secure MCP Tunnel. It exposes files in one configured
workspace and only administrator-defined fixed tasks. It is not a hosted
service or public MCP endpoint.

| Part | Includes |
|---|---|
| Core | Tunnel setup/diagnosis helpers, bounded workspace file tools and fixed tasks |
| Optional | Isolated jobs for separately installed Codex, Claude Code or OMP CLIs |

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

[Detailed guide](docs/guide.md) · [Design](DESIGN.md) ·
[Example config](config.example.json) · [License](LICENSE)
