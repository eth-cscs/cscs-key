# CSCS-key

CSCS-key is a command-line tool to manage SSH keys for the Swiss National Supercomputing Centre (CSCS). It allows users to add, remove, and list SSH keys associated with their CSCS account.

## Installation

Download the latest release from the [GitHub repository](0https://github.com/cscs/cscs-key/releases) and unpack the archive. Move the `cscs-key` executable to a directory in your PATH.
```bash
tar -zxf cscs-key-<version>.tar.gz
```

TODO brew, pip, ...

# Build from source

Prerequisites:
- Rust
- Cargo

You can install the prerequisites, e.g., using Homebrew on macOS:
```bash
brew install rust
```

Clone the repository and build the project:
```bash
git clone TODO URL
cd cscs-key
cargo build --release
```

## Usage

### Sign ssh key

To sign an SSH key, use the following command:
```bash
cscs-key sign
```
The default key is `~/.ssh/cscs-key`. You can specify a different private key using the `-f, --file` option.

The default duration of the signed key is 1 day. You can specify a different duration using the `-d, --duration` option. Possible values are `1d` or `1min`.

### Generate ssh key on the server (deprecated)

Generating the ssh key on the server is deprecated and will be removed in the future. It is recommended to generate the SSH key locally and then sign it using the `cscs-key sign` command.

To generate a new SSH key on the server, use the following command:
```bash
cscs-key gen
```
The default key is `~/.ssh/cscs-key`. You can specify a different private key using the `-f, --file` option.

The default duration of the signed key is 1 day. You can specify a different duration using the `-d, --duration` option. Possible values are `1d` or `1min`.

### List ssh keys

To list all valid SSH keys associated with your CSCS account, use the following command:
```bash
cscs-key list
```
Or with `-a, --all` to also show expired and revoked keys:
```bash
cscs-key list -a
```

### Revoke ssh key

To revoke one or more SSH key, use the following command:
```bash
cscs-key revoke <key_id> ...
```
Or to revoke all keys, use the `-a, --all` option:
```bash
cscs-key revoke -a
```

## Authentication

Users authenticate using the Open ID Connect (OIDC) protocol. The tool opens a web browser where the user authenticates with the CSCS credentials. After successful authentication, an access token is stored locally. This way users only need to authenticate about once per day.

Service accounts used for example in CI/CD pipelines can authenticate using an API key. Export the API key as an environment variable `CSCS_API_KEY`:
```bash
export CSCS_API_KEY=<your_api_key>
```
Pro tip: Use pipeline variables to securely store the API key in your CI/CD setup.
