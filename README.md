# CSCS-key

CSCS-key is a command-line tool to manage SSH keys for the Swiss National Supercomputing Centre (CSCS). It allows users to sign, list, and revoke SSH keys associated with their CSCS account.

## Installation

Download the latest release from the [GitHub releases page](https://github.com/eth-cscs/cscs-key/releases) and unpack the archive. Move the `cscs-key` executable to a directory in your PATH.

```bash
tar -zxf cscs-key-<version>.tar.gz
mv cscs-key ~/.local/bin/
```

## Build from source

Prerequisites: Rust and Cargo. Install via [rustup](https://rustup.rs/):

```bash
brew install rust
# or
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository and build:

```bash
cargo install --locked --git https://github.com/eth-cscs/cscs-key
```

This produces a native binary on macOS and Windows. On Linux, see below for a more portable build.

### Linux (MUSL static binary)

A standard `cargo build` on Linux links against the system's glibc, which may be too new for older distributions. For a fully static binary that runs on any x86_64 Linux system, use [cross](https://github.com/cross-rs/cross), which requires Docker or Podman:

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
```

The resulting binary is at `target/x86_64-unknown-linux-musl/release/cscs-key`.

## Usage

### Generate a local SSH key pair (first-time setup)

`cscs-key sign` requires both a private key (`~/.ssh/cscs-key`) and its matching public key (`~/.ssh/cscs-key.pub`). If you do not have a fresh pair, generate a fresh one first:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/cscs-key
```

### Sign an SSH key

Sign the public key to obtain a certificate valid for CSCS systems:

```bash
cscs-key sign
```

The default key path is `~/.ssh/cscs-key`. Specify a different key with `-f, --file`.

The default certificate validity is 1 day. Override with `-d, --duration` (`1d` or `1min`).

### List SSH keys

```bash
# List valid keys
cscs-key list

# Include expired and revoked keys
cscs-key list -a
```

### Revoke SSH keys

```bash
# Revoke specific keys by serial number
cscs-key revoke <serial_number> ...

# Revoke all active keys
cscs-key revoke -a

# Dry run: show what would be revoked
cscs-key revoke -a --dry
```

### Generate shell completion

```bash
cscs-key completion <shell>
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

To enable completion on every shell start, add to your shell config (e.g. `~/.bashrc`):

```bash
source <(cscs-key completion bash)
```

## Authentication

Users authenticate via OpenID Connect (OIDC). The tool opens a browser for login with CSCS credentials. The resulting token is cached locally so re-authentication is only needed about once per day.

When using **Service accounts in CI/CD**: Set the `CSCS_API_KEY` environment variable to skip browser login:

```bash
export CSCS_API_KEY=<service_account_api_key>
```

Store the key in your pipeline's secret/variable store rather than in code.
