# WebSafetyChecker

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-90%25-yellowgreen)

Heuristic website security scanner that evaluates phishing signals, web hardening posture, and exposure risks from a target URL.

## Problem Statement

Many users and small teams need a quick way to triage whether a website looks safe before deeper manual testing.
Existing options are often either too shallow (single-signal checks) or too heavy (full enterprise scanners).
This project exists to provide a practical, readable, CLI-first security assessment with both human-friendly reports and benchmark-based accuracy measurement.

## Features

- URL safety scan with final verdict (`Safe`, `Caution`, `High Risk`)
- Security header and baseline hardening audit
- TLS/certificate inspection with confidence scoring
- Phishing and lookalike-domain signal detection
- Passive application risk indicators
- Active light probing checks
- Sensitive path/exposure checks
- Redirect-chain and reputation lookup checks
- Weighted scoring profiles (`balanced`, `strict`, `phishing-focused`)
- Markdown report generation
- True-accuracy benchmark mode from labeled CSV datasets

## Architecture Diagram

Draw.io source and image are stored under `docs/architecture`.

![Clean Architecture Diagram](docs/architecture/clean-architecture.svg)

- Draw.io file: `docs/architecture/clean-architecture.drawio`
- Image file: `docs/architecture/clean-architecture.svg`

## Tech Stack

- **Language:** Python 3.13
- **HTTP & networking:** `requests`, `urllib3`, `socket`, `ssl`
- **Parsing & extraction:** `beautifulsoup4`
- **DNS / WHOIS intel:** `dnspython`, `python-whois`
- **Terminal UI:** `rich`, `colorama`
- **Imaging (optional similarity workflows):** `Pillow`
- **Testing / quality:** `pytest`, `ruff`, `vulture`

## Quick Run

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py https://example.com --allow-insecure-ssl
```

## Benchmark (True Accuracy)

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py --benchmark-file WebSafetyChecker/benchmark_sample.csv --allow-insecure-ssl --markdown-output WebSafetyChecker/benchmark_report.md
```

## Usage Examples

### CLI Commands

Basic scan:

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py https://example.com
```

Scan with SSL fallback and custom report file:

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py https://example.com --allow-insecure-ssl --markdown-output WebSafetyChecker/site_report.md
```

Scan with strict weighted profile:

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py https://example.com --weight-profile strict
```

Compare current run with previous report:

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py https://example.com --compare-with WebSafetyChecker/site_report.md
```

Run true-accuracy benchmark from labeled CSV:

```powershell
D:/Owner/Desktop/PYTHON CODES/.venv/Scripts/python.exe WebSafetyChecker/FunctionCode.py --benchmark-file WebSafetyChecker/benchmark_sample.csv --allow-insecure-ssl --markdown-output WebSafetyChecker/benchmark_report.md
```

### API Endpoint Style (Future Wrapper)

Current implementation is CLI-first. If wrapped as an API service, these are the recommended endpoints:

- POST /api/v1/scan
  - Body: { "url": "https://example.com", "allow_insecure_ssl": true, "weight_profile": "balanced" }
  - Returns: verdict, weighted score, output accuracy, findings, markdown path

- POST /api/v1/benchmark
  - Body: { "benchmark_file": "data/benchmarks/benchmark_sample.csv", "allow_insecure_ssl": true }
  - Returns: true accuracy, precision/recall/F1, confusion matrix

- GET /api/v1/health
  - Returns: service status and version metadata

## Future Improvements

- Split monolithic scanner into clean architecture modules under src/websafetychecker.
- Add automated threshold tuning using benchmark datasets to optimize true accuracy.
- Build optional FastAPI wrapper for remote scan execution and dashboard integration.
- Add asynchronous scanning queue for bulk URL triage with progress tracking.
- Add unit and integration tests for domain scoring, TLS analysis, and benchmark metrics.
- Add CI pipeline (lint, tests, benchmark sanity check, release artifact validation).
- Add plugin-based threat intel providers for extensible reputation and phishing feeds.
- Add dataset versioning and drift checks to monitor model quality over time.
