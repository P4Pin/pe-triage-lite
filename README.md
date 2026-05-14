# PE Triage Lite

PE Triage Lite is a lightweight reverse engineering assistant for fast PE file analysis.

The tool analyzes Windows executables (`.exe`, `.dll`) and generates reverse-oriented reports with:

- architecture detection
- PE sections
- imports analysis
- suspicious API clusters
- risk scoring
- reverse engineering hints
- markdown reports

The project is designed for:

- reverse engineering
- crackme solving
- malware triage
- Windows binary research
- beginner-to-intermediate RE workflows

---

# Features

## PE Analysis

- x86 / x64 detection
- image base
- entrypoint RVA
- PE sections
- entropy analysis

## Import Analysis

The tool extracts imported APIs and groups suspicious functionality into categories:

- anti-debug
- process execution
- memory injection
- networking
- string validation

## Reverse Hints

PE Triage Lite attempts to reduce noise and provide practical reverse engineering guidance.

Example:

```text
Windows dialog APIs detected.
Focus on DialogProc / WM_COMMAND handler.
Look for GetDlgItemTextA/W usage.
```

## Risk Scoring

The tool calculates a lightweight risk score:

```text
Low
Medium
High
```

based on detected API patterns.

---

# Project Structure

```text
pe-triage-lite/
│
├── Dockerfile
├── requirements.txt
├── README.md
│
├── app/
│   ├── main.py
│   ├── pe_parser.py
│   ├── heuristics.py
│   └── report.py
│
├── rules/
│   └── suspicious_apis.json
│
├── reports/
│
└── samples/
```

---

# Docker Usage

## Build

```bash
docker build -t pe-triage-lite .
```

## Run

```bash
docker run --rm -v "${PWD}:/work" pe-triage-lite samples/encoder.EXE
```

---

# Example Output

```text
Architecture: x86
Risk score: 0/100
Priority: Low

Reverse Hints:
- Windows dialog APIs detected.
- Focus on DialogProc / WM_COMMAND handler.
```

---

# Current Capabilities

- PE parsing
- import extraction
- entropy inspection
- reverse hints
- markdown report generation
- suspicious API heuristics

---

# Planned Features

## V1.5

- ASCII string extraction
- UTF-16 string extraction
- suspicious string detection

## V1.6

- packed binary heuristics
- import-less binary detection
- section anomaly detection

## V1.7

- HTML reports
- colored terminal output
- plugin system

---

# Technologies

- Python
- Docker
- pefile
- markdown reporting

---

# Goals

This project focuses on building practical reverse engineering workflows while keeping the tool lightweight and understandable.

The goal is not to replace professional frameworks, but to assist analysts during initial triage and binary inspection.
