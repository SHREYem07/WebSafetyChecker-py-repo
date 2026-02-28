# Architecture

This project follows a clean, layered structure so responsibilities stay separated and easy to maintain.

## Proposed Repository Structure

```text
WebSafetyChecker/
├─ FunctionCode.py
├─ FunctionCode_architecture.md
├─ README.md
├─ src/
│  └─ websafetychecker/
│     ├─ presentation/      # CLI and output formatting
│     ├─ application/       # use-cases/orchestration
│     ├─ domain/            # business rules, risk scoring models
│     └─ infrastructure/    # HTTP, DNS, WHOIS, filesystem, external services
├─ tests/
├─ data/
│  └─ benchmarks/
├─ docs/
│  └─ reports/
└─ pyproject.toml
```

## Layer Responsibilities

- **presentation**: handles command-line arguments, terminal rendering, and markdown report output.
- **application**: coordinates scan workflows and benchmark execution.
- **domain**: contains scoring logic, risk classification, and pure business rules.
- **infrastructure**: performs I/O operations (network calls, TLS checks, DNS/WHOIS lookups, file read/write).

## Dependency Rule

Dependencies should point inward:

- `presentation -> application -> domain`
- `infrastructure -> domain` (through interfaces/contracts when possible)
- `domain` should not depend on outer layers.

## Migration Plan (from current monolith)

1. Move CLI entrypoint code into `presentation/cli.py`.
2. Move orchestration (`analyze_website`, benchmark flows) into `application` services.
3. Move scoring and verdict logic into `domain`.
4. Move requests/DNS/TLS/WHOIS integrations into `infrastructure`.
5. Keep thin adapters in presentation for terminal + markdown output.

## Git Notes

- Keep generated reports under `docs/reports/` or ignore them in `.gitignore`.
- Keep sample benchmark datasets in `data/benchmarks/`.
- Use small, focused commits per layer migration.
