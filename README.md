# AI Dev Security Setup

A script for Ubuntu/Debian that creates a dedicated `ai-dev` user and runs coding
CLIs inside a [Bubblewrap](https://github.com/containers/bubblewrap) sandbox.
Claude Code, Kimi Code, Pi, and OpenCode are supported.

Third-party model APIs are routed through [LiteLLM](https://docs.litellm.ai/), a
local OpenAI-compatible gateway. Provider keys stay on the host and never enter
the sandbox.

> The script changes system settings as root: it creates a user, nftables rules,
> ACLs, systemd units, and launchers. Run it only on a machine you control, and
> read the [Security](#security) section first.

## Table of contents

- [What the script does](#what-the-script-does)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Command-line options](#command-line-options)
- [Usage](#usage)
- [LiteLLM for third-party APIs](#litellm-for-third-party-apis)
- [Security](#security)
- [Maintenance and uninstall](#maintenance-and-uninstall)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)
- [Development](#development)
- [License](#license)

## What the script does

1. Creates a system user `ai-dev` with no password, login shell, or sudo
   access.
2. Installs the selected CLIs into `/opt/ai-tools` as `ai-dev`, then seals the
   runtime: files become root-owned, setuid/setgid bits and dangerous symlinks
   are removed.
3. Configures ACLs on the shared directory `SHARED_DIR`: the owner and `ai-dev`
   get `rwX`, other local users get nothing.
4. Creates the bind-mount alias `SHARED_SOURCE` (default
   `/srv/ai-dev-shared`) so `ai-dev` does not need traverse access to the
   owner's home directory.
5. Installs nftables rules: internet and DNS are allowed; the local network and
   loopback are mostly blocked. The exceptions are OpenCode IPC and the local
   LiteLLM gateway.
6. Creates root-owned launchers `/usr/local/bin/*-secure` that start the
   selected CLI inside Bubblewrap.
7. Generates the OpenCode config for LiteLLM and the secrets file
   `/home/ai-dev/.secrets/env`.
8. Creates an owner-side SSH deploy key (the private key is never mounted into
   the sandbox).
9. On Ubuntu 24.04+, where unprivileged user namespaces are restricted by
   AppArmor, loads a targeted profile for `/usr/bin/bwrap`.
10. At the end, runs isolation checks: sudo, access to the owner's home,
    SSH keys, `/etc/shadow`, loopback, DNS/HTTPS, and CLI startup.

## Requirements

- Ubuntu 22.04/24.04+ or Debian with systemd, apt, and nftables.
- Root access via `sudo`.
- The owner (the user you run the script as) must have sudo rights: the
  launchers use `sudo -u ai-dev`.
- `SHARED_DIR` must be an existing directory **inside the owner's home**,
  absolute, with no spaces or special characters. Allowed characters are
  `A-Z a-z 0-9 . _ / -`.
- Internet access for apt and the official CLI installers.
- Python 3 (used to generate configs and run checks).
- For Pi, the script downloads and SHA256-verifies Node.js 22 for the machine
  architecture.

The script targets a single-owner workstation. It is not a multi-tenant
platform and not a replacement for a virtual machine.

## Quick start

```bash
git clone https://github.com/QNester/ai-dev-security-setup.git
cd ai-dev-security-setup

sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh
```

The script asks which CLI to install:

```text
1) Claude Code
2) Kimi Code
3) Pi
4) OpenCode
```

You can enter numbers or names separated by spaces or commas. Claude Code is
selected by default.

Non-interactive run:

```bash
sudo SHARED_DIR=/home/alice/projects \
  bash setup-ai-sandbox.sh --cli claude,opencode --yes
```

After installation:

```bash
# Key for the local LiteLLM gateway (see below)
sudo -u ai-dev nano /home/ai-dev/.secrets/env

cd /home/alice/projects
claude-secure        # or kimi-secure, pi-secure, opencode-secure
```

On first launch, the CLI asks you to authenticate. Credentials are stored in
`/home/ai-dev`, not in the owner's home directory.

### What happens during installation

- The following packages are installed: `bubblewrap`, `acl`, `nftables`,
  `curl`, `ca-certificates`, `git`, `openssh-client`, `python3`, `file`, and
  other utilities.
- Official CLI installers are downloaded over HTTPS and executed **as
  `ai-dev`**, not as root.
- `ai-dev` gets the primary group `ai-dev` and only the supplementary group
  `ai-dev-share`; the password and login shell are disabled.
- A bind-mount entry is added to `/etc/fstab`; nftables gets the
  `ip ai_dev_isolation` and `ip6 ai_dev_isolation` tables; systemd gets the
  `ai-dev-isolation.service` unit.

## Command-line options

```text
sudo bash setup-ai-sandbox.sh [--cli LIST] [--skip-cli] [--uninstall] [--yes]
```

| Option | Description |
| --- | --- |
| `--cli LIST` | Comma- or space-separated list of CLIs: `claude`, `kimi`, `pi`, `opencode` (numbers `1`–`4` are also accepted). If omitted, the script asks interactively. |
| `--skip-cli` | Do not download or update CLIs; keep the current selection. Useful for regenerating configs, ACLs, and firewall rules. |
| `--uninstall` | Remove system integration, ACLs, and launchers. The `ai-dev` user, its home, and the secrets file are kept. |
| `--yes`, `-y` | Do not ask questions. Required for non-interactive runs. |
| `-h`, `--help` | Show the built-in help. |

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `SHARED_DIR` | — (required) | Shared project directory. Must be inside the owner's home. |
| `AI_USER` | `ai-dev` | Name of the isolated user. |
| `OWNER_USER` | `$SUDO_USER` or `$USER` | Owner on whose behalf the launchers run. |
| `OWNER_HOME` | owner's home | Owner's home directory. |
| `SHARED_SOURCE` | `/srv/ai-dev-shared` | Bind-mount alias for `SHARED_DIR`. Must not overlap `SHARED_DIR`, either home, or system paths. |
| `OWNER_SSH_KEY` | `$OWNER_HOME/.ssh/ai-dev-deploy` | Owner-side deploy key path. The private key is not mounted into the sandbox. |
| `AI_SECRETS_FILE` | `/home/ai-dev/.secrets/env` | Secrets file loaded inside the sandbox. |
| `MAX_REVIEW_BYTES` | `1048576` | Maximum file size for `ai-review-file`. |
| `LITELLM_BASE_URL` | `http://127.0.0.1:4000/v1` | OpenAI-compatible LiteLLM endpoint. |
| `LITELLM_MODELS` | auto-detected | Comma- or space-separated list of model IDs. |
| `LITELLM_DEFAULT_MODEL` | first model in the list | Default model for OpenCode. |
| `LITELLM_ENV_FILE` | `./litellm.env` next to the script | File whose provider key **names** are read during detection. The script never sources it. |

Example with explicit models:

```bash
sudo SHARED_DIR=/home/alice/projects \
  LITELLM_BASE_URL=http://127.0.0.1:4000/v1 \
  LITELLM_MODELS="anthropic/claude-sonnet-4-5,openai/gpt-4o" \
  LITELLM_DEFAULT_MODEL=anthropic/claude-sonnet-4-5 \
  bash setup-ai-sandbox.sh --cli opencode --yes
```

## Usage

### Launchers

After installation, the following commands are available:

| Command | CLI |
| --- | --- |
| `claude-secure` | Claude Code |
| `kimi-secure` | Kimi Code |
| `pi-secure` | Pi |
| `opencode-secure` | OpenCode |
| `ai-review-file` | Static file review through Claude Code (only when Claude Code is selected) |

Run them from the owner's home directory:

```bash
cd /home/alice/projects/my-app
opencode-secure
```

The launcher starts in the current directory if it is inside `SHARED_DIR`;
otherwise it starts at the root of `SHARED_DIR`. You may be asked for your sudo
password.

Inside the sandbox:

- the `SHARED_DIR` working tree is writable;
- `/home/ai-dev` is writable;
- `/tmp` is a separate directory, `/var/lib/ai-sandbox/tmp`;
- `/usr`, `/opt/ai-tools`, and a minimal set of `/etc` files are read-only;
- the owner's home, its `.ssh`, and other host files are not accessible;
- there are no SSH keys and no agent forwarding;
- auto-update and telemetry are disabled where the CLI supports it.

### File review (Claude Code only)

```bash
ai-review-file /home/alice/projects/my-app/untrusted-script.sh
```

The command mounts the file read-only at `/review`, does not load secrets, and
restricts Claude Code tools to read-only access. The model still receives the
file contents, and a `SAFE` verdict is not permission to execute anything.
Claude Code v2.1.248 or newer is required (it uses `--restricted`). The maximum
file size is controlled by `MAX_REVIEW_BYTES`.

## LiteLLM for third-party APIs

### Why LiteLLM

Project policy: **access to third-party model APIs goes through LiteLLM**. This
provides:

- one OpenAI-compatible endpoint for OpenCode and other CLIs;
- Anthropic, OpenAI, Google, OpenRouter, and other provider keys stay on the
  host instead of entering the sandbox;
- the ability to issue the agent a separate virtual key with a budget and
  limits instead of the master key;
- centralized switching between models and providers.

Architecture:

```text
┌──────────────────────────────┐        ┌──────────────────────────┐
│ sandbox (ai-dev)             │        │ host                     │
│  OpenCode / another CLI      │        │  LiteLLM 127.0.0.1:4000  │
│  LITELLM_API_KEY=sk-...      │───────▶│  litellm.env             │
└──────────────────────────────┘  HTTP  └────────────┬─────────────┘
                                                     │
                                      ┌──────────────┼──────────────┐
                                      ▼              ▼              ▼
                                  Anthropic       OpenAI        other APIs
```

The script configures LiteLLM automatically only for OpenCode. Other CLIs can
also use LiteLLM if they support an OpenAI-compatible base URL; their
configuration is done separately.

### 1. Install LiteLLM

Using a dedicated venv (recommended):

```bash
python3 -m venv "$HOME/.venvs/litellm"
"$HOME/.venvs/litellm/bin/pip" install --upgrade pip
"$HOME/.venvs/litellm/bin/pip" install 'litellm[proxy]'
```

If `python3 -m venv` is unavailable, install the package:
`sudo apt-get install -y python3-venv`.

Or use `pipx`:

```bash
sudo apt-get install -y pipx
pipx install 'litellm[proxy]'
```

Docker alternative:

```bash
docker run --rm --name litellm \
  --env-file litellm.env \
  -p 127.0.0.1:4000:4000 \
  -v "$PWD/litellm.config.yaml:/app/config.yaml:ro" \
  ghcr.io/berriai/litellm:main-latest \
  --config /app/config.yaml
```

### 2. Create the configuration

The repository contains templates:

```bash
cp litellm.env.example litellm.env
cp litellm.config.example.yaml litellm.config.yaml
chmod 600 litellm.env
```

Fill in `litellm.env`:

- `LITELLM_MASTER_KEY` — the proxy key (use a long random value, e.g.
  `sk-...`);
- keys only for the providers you use;
- `DATABASE_URL` if you need virtual keys and budgets.

`litellm.env` and `litellm.config.yaml` are already in `.gitignore` — do not
commit them.

Configure `model_list` in `litellm.config.yaml`. The `model_name` values must
match the model IDs passed in `LITELLM_MODELS` and sent by OpenCode to LiteLLM.
The example includes Anthropic, OpenAI, Gemini, OpenRouter, Groq, DeepSeek,
xAI, Mistral, and Ollama; remove the entries you do not use.

### 3. Start the proxy

```bash
./start-litellm.sh
```

If LiteLLM is installed in a venv and is not in `PATH`:

```bash
LITELLM_BIN="$HOME/.venvs/litellm/bin/litellm" ./start-litellm.sh
```

The script reads `litellm.env` and `litellm.config.yaml`, checks that the key is
present, and starts the proxy on `127.0.0.1:4000`. Do not run it as root and do
not bind it to `0.0.0.0`: the sandbox only allows the loopback address and port
configured during installation.

Verify:

```bash
curl -s http://127.0.0.1:4000/v1/models \
  -H "Authorization: Bearer <LITELLM_MASTER_KEY>"
```

### 4. Pass the settings to the installer

By default, the script already uses `http://127.0.0.1:4000/v1`. If the address,
port, or models differ:

```bash
sudo SHARED_DIR=/home/alice/projects \
  LITELLM_BASE_URL=http://127.0.0.1:4000/v1 \
  LITELLM_MODELS="anthropic/claude-sonnet-4-5,openai/gpt-4o" \
  LITELLM_DEFAULT_MODEL=anthropic/claude-sonnet-4-5 \
  bash setup-ai-sandbox.sh --cli opencode
```

If `LITELLM_MODELS` is not set, the script detects models from the key names in
`litellm.env` (the file is read as text, never executed):

| Key in `litellm.env` | Default model |
| --- | --- |
| `ANTHROPIC_API_KEY` | `anthropic/claude-sonnet-4-5` |
| `OPENAI_API_KEY` | `openai/gpt-4o` |
| `GEMINI_API_KEY` | `gemini/gemini-2.5-pro` |
| `OPENROUTER_API_KEY` | `openrouter/anthropic/claude-sonnet-4-5` |
| `GROQ_API_KEY` | `groq/llama-3.3-70b-versatile` |
| `DEEPSEEK_API_KEY` | `deepseek/deepseek-chat` |
| `XAI_API_KEY` | `xai/grok-3` |
| `MISTRAL_API_KEY` | `mistral/mistral-large-latest` |
| `OLLAMA_API_BASE` | `ollama/llama3.2` |

The first detected key becomes the default model unless
`LITELLM_DEFAULT_MODEL` is set. If the default model is not in the list, the
script prepends it.

### 5. Key for the sandbox

The sandbox does not receive provider keys. It only needs a LiteLLM key:

```bash
sudo -u ai-dev nano /home/ai-dev/.secrets/env
```

```bash
LITELLM_API_KEY='sk-...'
```

This value must match `LITELLM_MASTER_KEY` from `litellm.env` **or** be a
separate virtual key. A virtual key with a budget is preferred: the master key
grants access to every provider configured in LiteLLM. Virtual keys require a
database (`DATABASE_URL`) in LiteLLM.

The `LITTLE_LLM_API_KEY` alias is supported: if `LITELLM_API_KEY` is empty, it
is used instead. The file must be owned by `ai-dev` and have mode `600`.
`ai-review-file` does not load this file.

All selected CLIs receive `LITELLM_API_KEY` inside the sandbox, but OpenCode
also gets a ready-made config:

```text
/home/ai-dev/.config/opencode/ai-sandbox-litellm.json
```

The config is selected through `OPENCODE_CONFIG` and does not replace the
global OpenCode config. It lists the models from `LITELLM_MODELS` or
auto-detection.

### 6. Network rules

During installation, the script allows `ai-dev` TCP access only to the IPv4
address and port from `LITELLM_BASE_URL`, if the address is loopback. All other
loopback destinations remain blocked. If LiteLLM listens on a non-loopback
address, no exception is created, and the sandbox will most likely be unable to
reach it.

After changing the address or port, rerun the installer with `--skip-cli` to
regenerate the nftables rules.

Do not run an unrelated service on the same address and port: the agent would
get network access to it.

### 7. OpenCode

OpenCode v2 uses a local TCP server for TUI/API communication. The script pins
it to `127.0.0.2:49374` and allows only that address and port plus the
configured LiteLLM endpoint. Do not change the OpenCode service hostname/port
and do not use `--standalone`: it picks a random port that the firewall will
block.

## Security

### What the isolation gives you

- A separate unprivileged user without sudo, password, or login shell.
- A root-owned CLI runtime; the agent cannot silently modify its own binaries.
- The host filesystem is hidden except for `SHARED_DIR`, `/home/ai-dev`,
  `/tmp`, and read-only system paths.
- No access to the owner's home, `.ssh`, `/etc/shadow`, or the owner-side
  deploy key.
- Network rules block LAN and loopback except for explicit exceptions.
- Secrets are not loaded in review mode.

### Limitations

Read this before use:

- The sandbox **is not a virtual machine** and does not protect against bugs in
  the kernel, Bubblewrap, AppArmor, or nftables.
- The agent can modify everything in `SHARED_DIR`, including `.git/hooks`,
  package scripts, `.envrc`, and editor tasks. Review diffs before running
  anything outside the sandbox. A separate clone or a single-project directory
  is safer.
- Existing `.env` files and Git credentials inside `SHARED_DIR` are readable by
  the agent.
- `/home/ai-dev/.secrets/env` is available to every sandboxed tool except
  `ai-review-file`. The agent can read and modify it. Use scoped/revocable keys
  with limits, not long-lived personal tokens.
- The generated OpenCode config and the secrets file live in `/home/ai-dev`, so
  the agent can modify them. The LiteLLM key is exposed to the agent as well.
  Use a virtual key with a budget instead of the master key.
- The sandbox intentionally allows `ai-dev` to reach the configured LiteLLM
  loopback address. Do not run other services on that address/port and do not
  expose LiteLLM to the LAN.
- Internet access is allowed. LAN filtering is best-effort: NAT hairpin,
  global-IPv6 peers, abstract Unix sockets, and other paths remain possible.
  For strong isolation, use a VM or a separate network namespace with a
  controlled proxy.
- DNS is allowed only to the nameservers from `/etc/resolv.conf` at install
  time, on port 53.
- The agent has no SSH key and no agent forwarding. Run Git/SSH outside the
  sandbox or deliberately use short-lived scoped credentials.
- Official CLI installers are fetched over HTTPS but without an independent
  signature or checksum (except Node.js for Pi, which is SHA256-verified). If
  that trust model is unacceptable, mirror and pin the installers.
- `ai-review-file` is susceptible to model mistakes and prompt injection. A
  `SAFE` verdict is not permission to execute. The model provider still
  receives the file contents.
- The CLI runtime is root-owned and world-readable because the sandbox runs as
  an unprivileged user. Do not put credentials in the installer HOME.
- On Ubuntu 24.04+, a targeted AppArmor profile allows `/usr/bin/bwrap` to
  create user namespaces. The profile is removed by `--uninstall`. Do not
  disable `kernel.apparmor_restrict_unprivileged_userns` globally unless
  necessary.
- `--uninstall` removes ACLs and the setgid bit but does not restore the
  original owning group of the shared directory.

## Maintenance and uninstall

### Updating CLIs and configuration

First stop all `ai-dev` sessions:

```bash
pgrep -a -u ai-dev
# exit the sandboxes or stop the processes
```

Then:

```bash
# update CLIs and regenerate everything
sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh --cli claude,opencode

# regenerate only configs/ACLs/firewall, leave CLIs untouched
sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh --skip-cli
```

The script is safe to rerun; it updates an existing installation and changes
the CLI selection via `--cli`.

### Checking status

```bash
systemctl status ai-dev-isolation.service
sudo nft list table ip ai_dev_isolation
sudo nft list table ip6 ai_dev_isolation
findmnt /srv/ai-dev-shared
sudo -u ai-dev ls -la /home/ai-dev/.config/opencode
```

### Uninstall

```bash
pgrep -a -u ai-dev   # should be empty
sudo SHARED_DIR=/home/alice/projects bash setup-ai-sandbox.sh --uninstall
```

Removed:

- nftables tables, the systemd unit, and the nftables drop-in;
- the `ai-dev-bwrap-userns` AppArmor profile;
- `/usr/local/bin/*-secure` launchers and `ai-review-file`;
- `/opt/ai-tools` and `/var/lib/ai-sandbox/tmp`;
- the bind-mount alias and the `/etc/fstab` entry;
- ACLs, setgid bits, and `ai-dev-share` membership;
- the generated OpenCode config.

Kept:

- the `ai-dev` user and `/home/ai-dev`;
- `/home/ai-dev/.secrets/env` (review and delete it manually if not needed);
- the owner-side deploy key;
- the shared directory and its files.

The script refuses to remove the firewall while `ai-dev` processes are running:
removing the rules would immediately weaken isolation.

### Deploy key

Installation creates an ed25519 key:

```text
/home/alice/.ssh/ai-dev-deploy
/home/alice/.ssh/ai-dev-deploy.pub
```

The private key is not mounted into the sandbox. Add the public key as a
write-enabled deploy key on GitHub/GitLab:

- GitHub: **Settings → Deploy keys → Add deploy key**, paste the `.pub`
  contents, enable **Allow write access**.
- GitLab: **Settings → Repository → Deploy keys**, enable write access.

The public key is printed at the end of the installation.

## Troubleshooting

### `Unprivileged Bubblewrap is blocked`

On Ubuntu 24.04+, unprivileged user namespaces are restricted by AppArmor. The
script creates `/etc/apparmor.d/ai-dev-bwrap-userns`. Check it:

```bash
sudo apparmor_parser -Q /etc/apparmor.d/ai-dev-bwrap-userns
sudo aa-status | grep -A2 ai-dev-bwrap
```

If the profile cannot be loaded, fix it or run the sandbox in a VM. Disabling
`kernel.apparmor_restrict_unprivileged_userns=0` system-wide weakens protection
for the entire machine and is not recommended.

### LiteLLM is unreachable from the sandbox

1. Make sure the proxy listens on loopback and the expected port:
   `ss -ltnp | grep 4000`.
2. Check that `LITELLM_BASE_URL` used during installation matches the real
   address.
3. Rerun the installer with `--skip-cli` to update nftables.
4. Check the key: `curl` with `Authorization: Bearer ...` should return the
   model list.
5. Remember: a non-loopback address gets no firewall exception.

### OpenCode does not start or cannot connect

OpenCode must use `127.0.0.2:49374`. Check:

```bash
sudo -u ai-dev /opt/ai-tools/bin/opencode service get hostname
sudo -u ai-dev /opt/ai-tools/bin/opencode service get port
sudo -u ai-dev /opt/ai-tools/bin/opencode service get env OPENCODE_CONFIG
```

Do not use `--standalone` and do not change the port. If OpenCode was updated
and is no longer compatible with the config, rerun the installer without
`--skip-cli`.

### `Stop all ai-dev processes before ...`

```bash
pgrep -a -u ai-dev
# close the sessions, then if necessary:
sudo pkill -TERM -u ai-dev
```

If the processes do not exit, check for a running OpenCode service or CLI
installer.

### `SHARED_DIR must ...` error

`SHARED_DIR` must:

- be absolute;
- exist at install time;
- be inside the owner's home;
- contain only `A-Z a-z 0-9 . _ / -`;
- not overlap the `ai-dev` home or `SHARED_SOURCE`.

### Pi does not install on an exotic architecture

Supported architectures are `x86_64`, `aarch64`, `armv7l`, `ppc64le`, and
`s390x`. For other architectures, install Node.js 22 manually into
`/opt/ai-tools/node` or do not select Pi.

### `sudo: a password is required`

The launchers call `sudo -u ai-dev`. The owner must have sudo rights. If you
need non-interactive launches, configure sudoers deliberately; the script does
not add such rules itself.

## Repository layout

```text
.
├── setup-ai-sandbox.sh              # main installer
├── start-litellm.sh                 # starts the local LiteLLM proxy
├── litellm.env.example              # keys and master key template
├── litellm.config.example.yaml      # LiteLLM model_list template
├── README.md
├── SECURITY.md                      # vulnerability reporting policy
├── LICENSE
├── .gitignore
└── .gitattributes
```

## Development

Basic syntax check:

```bash
bash -n setup-ai-sandbox.sh
bash -n start-litellm.sh
```

If ShellCheck is installed:

```bash
shellcheck setup-ai-sandbox.sh start-litellm.sh
```

The script changes system settings, so test changes in a disposable VM or a
systemd-capable container, not on a production machine. There is no automated
test suite; the installer runs its own isolation checks at the end.

## License

MIT. See [LICENSE](LICENSE).
