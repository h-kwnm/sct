# sct

A command-line tool for inspecting [Certificate Transparency](https://certificate.transparency.dev/).
Both tiled logs using the [Static CT API](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) and
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) logs are supported.

## Requirements

- Go 1.24 or later

## Installation

```sh
go install github.com/h-kwnm/sct@latest
```

## Tool-specific commands

These commands are not defined by either RFC 6962 or Static CT API specification.
They include tool management (logs, version) and simulation/inspection utilities (`get-sct`, `audit-path`, `audit-tile`).

### `logs` - List CT logs

Fetches the log list from [Google's repository](https://www.gstatic.com/ct/log_list/v3/log_list.json) and caches it locally. Subsequent invocations use the cache.

```sh
sct logs
sct logs --refresh          # re-fetch from Google
sct logs --state <state>    # filter by state (usable, readonly, retired, qualified, pending, rejected)
sct logs --type <type>      # filter by API type ("static" for Static CT API, "rfc6962" for RFC 6962)
```

The assigned **ID** is used by other commands to identify a log.

### `get-sct` - Extract SCT extension contents

Extracts SCT extension contents from a PEM-formatted certificate file specified by `--pem`
or `--url` and prints them as JSON.
When a certificate is specified by `--url` option, certificate verification can be skipped by `--insecure` option.

```sh
sct get-sct --pem <pem-file>          # pass certificate from local PEM file
sct get-sct --url <url> [--insecure]  # fetch certificate from the URL
```

### `audit-path` - Print audit path for a specified combination of leaf index and tree size

Prints the audit path in JSON format.
This path consists of Merkle Tree Nodes in the form of `{"start":m,"end":n}`, which corresponds to `MTH[m,n]`
format used in [RFC 6962's notation](https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1).

This command only simulates an audit path calculated based on the specified parameters.
No HTTP requests are made, thus no need to specify target log.

```sh
sct audit-path --index <leaf-index> --size <tree-size>  # no network requests made
```

### `audit-tile` - Print tiles for a specified combination of leaf index and tree size

Prints the tiles in JSON format.
The `tiles` field shows which tiles to fetch and which hash positions within each tile to use for proof verification.

This command only simulates which tiles would be fetched, calculated based on the specified parameters.
No HTTP requests are made, thus no need to specify target log.

```sh
sct audit-tile --index <leaf-index> --size <tree-size>  # no network requests made
```

### `version` - Print version

```sh
sct version
```

## Static CT API commands

These commands target Static CT API.
RFC 6962 logs do not support them, so the `--log` option must refer to a log of type `static` when needed.

### `checkpoint` - Fetch a log checkpoint

Fetches the current signed checkpoint from a log's monitoring URL and prints it as JSON.

```sh
sct checkpoint --log <id>
```

### `data` - Fetch a data tile

Fetches the data tile containing the given leaf index, parses its entries, and prints it as JSON.
Additionally, data tile entries including the leaf are saved as a JSON file when the `--out` option is specified.

```sh
sct data --log <id> --index <leaf-index>               # print the index's leaf certificate
sct data --log <id> --index <leaf-index> --out <dir>   # print the leaf and save whole tile entries to specific directory, e.g., /tmp
```

### `audit` - Verify whether the leaf at the given index is included in the log

Fetches the tiles required to verify the leaf certificate's inclusion and prints the fetched data and verification result as JSON.
The verification result is reported in the `verification_success` field of the JSON-formatted output.
The output includes information on which tiles and hashes are used for the verification.

See `audit-path` and `audit-tile` to simulate audit inputs without making network requests.

```sh
sct audit --log <id> --index <leaf-index>
```

## RFC 6962 commands

These commands target RFC 6962 API.
Static CT API logs do not support them, so the `--log` option must refer to a log of type `rfc6962` when needed.

### `get-sth` - Fetch a log's signed tree head

Fetches a signed tree head of the specified log and prints it as JSON.

```sh
sct get-sth --log <id>
```

### `get-proof-by-hash` - Fetch audit paths and verify them

Fetches audit paths related to SCTs included in the given certificate, or hash value when a log is specified.
The certificate is passed by either `--pem` or `--url` option. When passed by `--pem`,
the leaf certificate's issuer certificate must also be passed by `--iss` option.
When `--url` option is specified, both leaf and issuer certificates are automatically fetched from the endpoint.
Certificate verification can be skipped by `--insecure` option.
When leaf hash value is directly specified by `--hash` option, `--log` option is required.
This pattern is useful when you want to verify the inclusion proof using a leaf hash value present in the result of `get-entry-and-proof` command.

The verification result of the audit proof is reported in the `verification_success` field of the JSON-formatted output.
The `audit_proof` field contains the raw response from the CT log's get-proof-by-hash endpoint.
Target endpoints for get-proof-by-hash are automatically identified from log IDs in SCTs.

```sh
sct get-proof-by-hash --pem <leaf-cert-pem-file> --iss <issuer-cert-pem-file>
sct get-proof-by-hash --url <url> [--insecure]
sct get-proof-by-hash --log <id> --hash <base64-leaf-hash>
```

### `get-entries` - Fetch leaf certificate entries

Fetches one or more leaf certificate entries from the specified log.
Entries are identified by leaf index and offset. For example,
when the command is run with `--index 1560` and `--offset 3`, it fetches 4 entries - indices 1560 through 1563, inclusive.
Offset is 0 by default so only the entry specified by the leaf index is fetched when `--offset` is omitted.

```sh
sct get-entries --log <id> --index <leaf-index>                      # fetch only the index's entry
sct get-entries --log <id> --index <leaf-index> [--offset <offset>]  # fetch multiple (offset+1) entries starting with the index
```

### `get-entry-and-proof` - Fetch entry and its audit path

Fetches a leaf certificate entry, a certificate chain, and an audit path related to the entry from the specified log.
The entry is identified by leaf index specified by `--index`. The audit path is based on a tree size specified by `--size`.

```sh
sct get-entry-and-proof --log <id> --index <leaf-index> --size <tree-size>
```

Unlike `get-proof-by-hash`, this command does not verify the entry's inclusion by the audit path.
This is because the Signed Tree Head (STH) returned by the log server always reflects the current tree size,
which may not match the `--size` value passed to this command. Without a matching root hash, the proof cannot be verified.
If you want to verify inclusion of the entry, use `--hash` option in `get-proof-by-hash` command
by passing the hash value in the `leaf_hash` field with the log ID.

## RFC 6962 and Static CT API commands

These commands are based on RFC 6962, but target both RFC 6962 and Static CT API logs.
So both types of logs can be specified by `--log` option when needed.

### `get-roots` - Fetch a list of accepted root certificates

Fetches a list of root certificates accepted by the specified log and prints it as JSON.

```sh
sct get-roots --log <id>
```

### `add-chain` - Add a certificate entry to the log

Adds a certificate chain as a merkle tree leaf to the log server.
This is a mutating action at the specified log and cannot be reverted.
In other words, the added certificate will be recorded in the log permanently.
Be cautious not to use it in an abusive manner.

For example:

- Do not run this command excessive number of times, that could cause undesirable effect in the log.
- Do not add certificates indiscriminately, that might attract interested parties' attention as a potential threat.

The certificate and its certificate chain can be passed by `--pem` with `--chain` option or `--url` option.
When specified by `--url`, certificates are fetched by the endpoint automatically.

```sh
sct add-chain --log <id> --pem <leaf-cert-pem-file> --chain <cert-chain-pem-file>
sct add-chain --log <id> --url <url> [--insecure]
```

## Options

| Flag | Description |
|------|-------------|
| `--debug` | Enable debug logging (output to stderr). |
| `--insecure` | Only used in combination with `--url`. Skip TLS certificate verification of the server at the URL. |

```sh
sct --debug data --log 10 --index 1234567
```

```sh
sct get-sct --url https://example.com --insecure
```

## Cache

### Log (persistent, ~/.cache/sct/logs.json)

Log list is fetched and cached by the first invocation of `sct logs` command.
The log list is cached at `~/.cache/sct/logs.json`. Run `sct logs --refresh` to update it.

### Tile (ephemeral, deleted on reboot)

Tiles fetched during `audit` command invocation are cached in `sct` directory
under the system's cache directory, e.g., `/tmp/sct` in case of Linux environment.
Note that the cache is deleted after reboots.
The cache file name is first 12 hex characters of a hash value, derived from the tiles' respective URL.

## License

[MIT](LICENSE)
