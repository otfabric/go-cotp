# Contributing to otfabric/go-cotp

Thank you for your interest in contributing. This document explains how to get started.

## Development setup

- **Go**: 1.23 or later.

```sh
git clone https://github.com/otfabric/go-cotp.git
cd go-cotp
go mod download
```

## Running tests

- **Unit tests**: `make test` (runs `go test .` for the root package).
- **Race tests**: `make test-race` or rely on CI, which runs race tests.
- **Coverage**: `make coverage` for a report; `make coverage-check` to enforce minimum 75% coverage.
- **Fuzz**: `make fuzz` (or `fuzz-decode` / `fuzz-parse`) to run fuzz targets.

## Code style and linting

- Format code: run `gofmt` (or your editor’s “format on save”) on modified files; `make fmt` to format the tree.
- Lint: `make vet` and optionally `golangci-lint run` if installed.

Please run `make test` and `make vet` (and `make coverage-check`) before submitting a PR.

## Submitting changes

1. Open an issue or pick an existing one to discuss the change.
2. Fork the repo, create a branch, and make your changes.
3. Add or update tests as needed.
4. Run `make test`, `make vet`, and `make coverage-check`.
5. Open a pull request with a clear description and reference to the issue.

## Error handling

Prefer sentinel errors from `errors.go` and wrap with `%w` so callers can use `errors.Is` / `errors.As`. Avoid string-only error comparisons; always return typed/sentinel errors wrapped with context.

## Documentation

When you change **public API signatures** (function parameters, return types, or exported types), update:

- **[doc.go](doc.go)** — keep package documentation in sync.
- **[README.md](README.md)** — if it references the changed API or examples.
- **[docs/API.md](docs/API.md)** — keep the public API reference in sync.

Also keep doc comments on exported symbols in sync with behavior.
