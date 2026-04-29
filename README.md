# sct

A command-line tool for inspecting [Certificate Transparency](https://certificate.transparency.dev/) tiled logs using the [Static CT API](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md).

## Requirements

- Go 1.24 or later

## Installation

```sh
go install github.com/h-kwnm/sct@latest
```

## Commands

### `logs` — List CT logs

Fetches the log list from [Google's repository](https://www.gstatic.com/ct/log_list/v3/log_list.json) and caches it locally. Subsequent invocations use the cache.

```sh
sct logs
sct logs --refresh          # re-fetch from Google
sct logs --state usable     # filter by state (usable, readonly, retired, qualified, pending, rejected)
```

The assigned **ID** is used by other commands to identify a log.

### `checkpoint` — Fetch a log checkpoint

Fetches the current signed checkpoint from a log's monitoring URL and prints it as JSON.

```sh
sct checkpoint --log <id>
```

### `data` — Fetch a data tile

Fetches the data tile containing the given leaf index, parses its entries, and prints it as JSON.
Additionally, data tile entries including the leaf are saved as a JSON file when the `--out` option is specified.

```sh
sct data --log <id> --index <leaf-index>
sct data --log <id> --index <leaf-index> --out <dir>   # save to specific directory, e.g., /tmp
```

### `get-sct` — Extract SCT extension contents

Extracts SCT extension contents from a PEM-formatted certificate file and prints them as JSON.

```sh
sct get-sct --pem <pem-file>
```

### `audit` — Verify whether the leaf at the given index is included in the log

Verifies whether the leaf at the given index is included in the log.
The verification result is reported in the `verification_success` field of the JSON-formatted output.
The output includes information on which tiles and hashes are used for the verification.

```sh
sct audit --log <id> --index <leaf-index>
```

### `audit-path` — Print audit path for a specified combination of leaf index and tree size

Prints the audit path in JSON format.
This path consists of Merkle Tree Nodes in the form of `{"start":m,"end":n}`, which corresponds to `MTH[m,n]` format used in [RFC 6962's notation](https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1).

```sh
sct audit-path --index <leaf-index> --size <tree-size>
```

### `version` — Print version

```sh
sct version
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
