# Copilot Instructions for `ssl-tools`

## Build, test, and run

- Build CLI binary:
  - `go build ./cmd/ssl-tools`
- Run CLI directly:
  - `go run ./cmd/ssl-tools --help`
  - `go run ./cmd/ssl-tools version`
  - `go run ./cmd/ssl-tools check`
- Run all tests:
  - `go test ./...`
- Run a single test by name:
  - `go test ./... -run TestName`

## High-level architecture

- Entry point is `cmd/ssl-tools/main.go`, which forwards CLI args to `internal/cli.Run`.
- Command routing is centralized in `internal/cli/root.go`:
  - `version` prints `internal/version.String()`
  - `check` delegates to `internal/app.RunCheck(...)`
- Application command behavior lives under `internal/app/`.
- Shared reusable utilities are under `pkg/` (currently `pkg/output.Println` wraps terminal output).

## Repository-specific conventions

- Keep the executable entrypoint minimal; put command parsing in `internal/cli` and command logic in `internal/app`.
- Add new commands by extending the `switch` in `internal/cli/root.go` and delegating to a focused function in `internal/app`.
- Keep user-facing output routed through `pkg/output` helpers instead of scattering `fmt.Println` across app logic.
- Version text is sourced from `internal/version/version.go` (`current` constant + `String()`).
