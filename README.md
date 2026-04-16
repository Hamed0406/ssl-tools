# ssl-tools

A command-line tool written in Go for analyzing SSL/TLS certificates — from local files or live hosts.

---

## Features

- 🔍 Analyze local certificate files (`.pem`, `.cer`)
- 🌐 Connect to a live host and inspect the full TLS certificate chain
- 📋 Displays subject, issuer, validity, key type, SANs, and fingerprints
- ⚠️  Flags expired or soon-to-expire certificates
- 💾 Automatically saves results to a timestamped output file

---

## Installation

### Prerequisites

- [Go 1.21+](https://golang.org/dl/)

### Build from source

```bash
git clone <repo-url>
cd ssl-tools
go build -o ssl-tools ./cmd/ssl-tools
```

---

## Usage

```
ssl-tools <command> [arguments]

Commands:
  check <file>     Analyze a certificate file (.pem or .cer)
  host <hostname>  Check TLS certificate chain from a live host
  version          Print version
```

### Check a local certificate file

```bash
ssl-tools check mycert.pem
ssl-tools check mycert.cer
```

### Check a live host

```bash
ssl-tools host github.com
ssl-tools host myserver.com:8443
```

> Defaults to port **443** if no port is specified.

---

## Example Output

```
Checking TLS certificate chain for: github.com
Total certificates in chain: 3

[1/3] LEAF (Server)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CERTIFICATE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ Subject ]
  Common Name       : github.com

[ Issuer ]
  Common Name       : Sectigo Public Server Authentication CA DV E36
  Organization      : Sectigo Limited
  Country           : GB

[ Validity ]
  Not Before        : Fri, 06 Mar 2026 00:00:00 UTC
  Not After         : Wed, 03 Jun 2026 23:59:59 UTC
  Status            : VALID (48 days remaining)

[ Identity ]
  Serial Number     : 1D:C2:89:C1:EA:DA:FB:04:E9:D1:CF:53:D5:D7:22:53
  Signature Alg     : ECDSA-SHA256
  Is CA             : false

[ Public Key ]
  Key Type          : ECDSA
  Curve             : P-256

[ Subject Alternative Names ]
  DNS               : github.com
  DNS               : www.github.com

[ Fingerprints ]
  SHA-1             : AB:58:EA:...
  SHA-256           : 97:16:D3:...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Result saved to: output/host-github.com-20260416_213424.txt
```

---

## Output Files

Results are automatically saved as timestamped `.txt` files.

| Command | Output filename |
|---|---|
| `check mycert.pem` | `check-mycert.pem-<timestamp>.txt` |
| `host github.com` | `host-github.com-<timestamp>.txt` |

### Output folder

The output folder is resolved in this order:

1. `OUTPUT_FOLDER` environment variable (if set)
2. `output/` directory relative to the current working directory (auto-created if missing)

---

## Project Structure

```
ssl-tools/
├── cmd/
│   └── ssl-tools/
│       └── main.go           # Entry point
├── internal/
│   ├── app/
│   │   └── run.go            # Command implementations
│   ├── cert/
│   │   ├── analyze.go        # Certificate parsing and formatted output
│   │   └── remote.go         # TLS connection and cert chain retrieval
│   ├── cli/
│   │   └── root.go           # Command routing
│   └── version/
│       └── version.go        # Version string
├── pkg/
│   └── output/
│       ├── print.go          # Basic print helper
│       └── file.go           # Output folder and file management
├── .github/
│   └── copilot-instructions.md
└── go.mod
```

---

## Development

```bash
# Run directly
go run ./cmd/ssl-tools --help

# Build
go build ./cmd/ssl-tools

# Run tests
go test ./...

# Run a single test
go test ./... -run TestName
```

---

## Version

Current version: `0.1.0`
