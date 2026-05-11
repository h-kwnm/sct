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

## Common commands

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

Extracts SCT extension contents from a PEM-formatted certificate file or a given URL endpoint and prints them as JSON.

```sh
sct get-sct --pem <pem-file>
sct get-sct --url <url>
```

### `audit-path` - Print audit path for a specified combination of leaf index and tree size

Prints the audit path in JSON format.
This path consists of Merkle Tree Nodes in the form of `{"start":m,"end":n}`, which corresponds to `MTH[m,n]`
format used in [RFC 6962's notation](https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1).

```sh
sct audit-path --index <leaf-index> --size <tree-size>
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
sct data --log <id> --index <leaf-index>
sct data --log <id> --index <leaf-index> --out <dir>   # save to specific directory, e.g., /tmp
```

### `audit` - Verify whether the leaf at the given index is included in the log

Verifies whether the leaf at the given index is included in the log.
The verification result is reported in the `verification_success` field of the JSON-formatted output.
The output includes information on which tiles and hashes are used for the verification.

```sh
sct audit --log <id> --index <leaf-index>
```

### `audit-tile` - Print tiles for a specified combination of leaf index and tree size

Prints the tiles in JSON format.
The `tiles` field shows which tiles to fetch and which hash positions within each tile to use for proof verification.

```sh
sct audit-tile --index <leaf-index> --size <tree-size>
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

Fetches audit paths related to SCTs included in the given certificate.
The certificate is passed by either `--pem` or `--url` option. When passed by `--pem`,
the leaf certificate's issuer certificate must also be passed by `--iss` option.
When `--url` option is specified, both leaf and issuer certificates are automatically fetched from the endpoint.

The verification result is reported in the `verification_success` field of the JSON-formatted output.
Object under `audit_proof` is bare response against get-proof-by-hash API. Target endpoints for get-proof-by-hash are
automatically identified from log IDs in SCTs.

```sh
sct get-proof-by-hash --pem <leaf-cert-pem-file> --iss <issuer-cert-pem-file>
sct get-proof-by-hash --url <url>
```

## Options

| Flag | Description |
|------|-------------|
| `--debug` | Enable debug logging (output to stderr) |

```sh
sct --debug data --log <id> --index <leaf-index>
```

## Cache

The log list is cached at `~/.cache/sct/logs.json`. Run `sct logs --refresh` to update it.

## License

[MIT](LICENSE)
