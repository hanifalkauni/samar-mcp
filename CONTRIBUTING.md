# Contributing to Samar MCP Server

Thank you for your interest in contributing to **Samar**! Samar is built to protect developers, agents, and organizations from accidental credential leaks into LLM contexts.

We welcome bug reports, feature requests, code contributions, and security reviews.

---

## Prerequisites

- **Go**: 1.25 or higher (`go version`)
- **Git**: 2.30 or higher
- **Operating System**: Linux, macOS, or Windows

---

## Repository Structure

```text
samar-mcp/
├── cmd/
│   └── samar/            # Server entrypoint and MCP stdio handlers
├── internal/
│   ├── allowlist/        # Network destination allowlist & rule engine
│   ├── audit/            # JSONL security audit logger
│   ├── detector/         # Regexp & key-value credential detection
│   ├── idgen/            # Cryptographic random token ID generation
│   ├── leakscan/         # Output verification scanner
│   ├── masking/          # Inbound pseudonymization engine
│   ├── policy/           # Egress network inspection & confirmation
│   ├── restore/          # Outbound reversible detokenization
│   ├── safeio/           # Path normalization & safe I/O operations
│   └── server/           # MCP protocol routing & tool registrations
├── test/
│   ├── adversarial/      # Red-team attack suite & evasion tests
│   ├── canary/           # Canary leak verification harness
│   └── corpus/           # Known secret fixtures and samples
├── docs/                 # Architectural specifications and PRD
├── README.md             # English documentation
└── README.id.md          # Indonesian documentation
```

---

## Development Workflow

### 1. Fork & Clone
```bash
git clone https://github.com/hanifalkauni/samar-mcp.git
cd samar-mcp
git checkout -b feature/your-feature-name
```

### 2. Run Tests & Validation
Before submitting any changes, ensure all tests and linters pass:

```bash
# Verify dependencies
go mod verify

# Run static analysis
go vet ./...

# Run all unit and adversarial tests
go test -v ./...

# Run canary leak harness
go run ./test/canary
```

### 3. Build Binary Locally
```bash
# On Linux / macOS:
go build -trimpath -ldflags "-s -w" -o bin/samar ./cmd/samar

# On Windows:
go build -trimpath -ldflags "-s -w" -o bin/samar.exe ./cmd/samar
```

---

## Contribution Guidelines

1. **Security-First Mindset**: Samar follows the **Fail-Closed** design principle. If a token is corrupted or missing, operations must abort safely rather than leaking partially-resolved credentials.
2. **Deterministic Tokenization**: Identical raw secrets within a single session must resolve to the identical token (`__SAMAR_SECRET_<ID>__`).
3. **No External Telemetry**: Samar runs strictly locally on the user's machine. Do not introduce network calls, cloud tracking, or remote analytics.
4. **Bilingual Documentation**: When updating user-facing features or tool interfaces, please update both [README.md](README.md) and [README.id.md](README.id.md) to keep documentation synchronized.
5. **Code Style**:
   - Format all Go code using `gofmt` or `goimports`.
   - Maintain clear godoc comments on exported functions, types, and constants.

---

## Submitting Pull Requests

1. Commit your changes with clear, descriptive commit messages.
2. Push your feature branch to your fork.
3. Open a Pull Request targeting `main`.
4. Ensure the GitHub Actions CI workflow passes completely.
5. Provide a clear PR description explaining what was changed and how it was tested.
