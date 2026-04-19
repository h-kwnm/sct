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

Fetches the data tile containing the given leaf index, parses its entries, and saves them as a JSON file.

```sh
sct data --log <id> --index <leaf-index>
sct data --log <id> --index <leaf-index> --out <dir>   # save to specific directory
```

Output is written to `~/.cache/sct/` by default.

### `version` — Print version

```sh
sct version
```

## Options

| Flag | Description |
|------|-------------|
| `-debug` | Enable debug logging (output to stderr) |

```sh
sct -debug data --log <id> --index <leaf-index>
```

## Cache

The log list is cached at `~/.cache/sct/logs.json`. Run `sct logs --refresh` to update it.

## License

[MIT](LICENSE)
