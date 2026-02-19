# cvefind

`cvefind` is a CLI tool that collects CVE data for a package name from multiple advisory sources and merges the results into one view.

It is optimized for:
- Fast lookup by package name
- Lower miss rate by combining sources (OSV, GHSA, NVD)
- supports JSON/YAML output

## Features

- Multi-source collection:
  - [OSV](https://osv.dev/)
  - [GitHub Security Advisories (GHSA)](https://github.com/advisories)
  - [NVD](https://nvd.nist.gov/)
- CVE deduplication and source merge
- Optional inclusion of GHSA records that do not have CVE IDs yet
- Severity filtering (`low`, `medium`, `high`, `critical`)
- CVSS score/vector support (when available, typically from NVD)
- Output formats: `default`, `json`, `yaml`

## Installation

```bash
git clone https://github.com/sm1ee/cvefind.git
cd cvefind
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

## Help

```bash
cvefind --help
                                                                           
 Usage: cvefind [OPTIONS] PACKAGE_NAME                                     
                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────╮
│ *    package_name      TEXT  Package name. Example: n8n [required]      │
╰─────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────╮
│ --ecosystem             -e      TEXT   Package ecosystem [default: npm] │
│ --alias                 -a      TEXT   Additional search alias.         │
│                                        Repeatable.                      │
│ --include-ghsa-pending                 Include GHSA advisories that do  │
│                                        not have a CVE yet.              │
│ --min-severity                  TEXT   Filter by minimum severity: low, │
│                                        medium, moderate, high,          │
│                                        critical.                        │
│ --output                -o      TEXT   Output format: default, json,    │
│                                        yaml.                            │
│                                        [default: default]               │
│ --timeout                       FLOAT  HTTP timeout (seconds)           │
│                                        [default: 20.0]                  │
│ --help                                 Show this message and exit.      │
╰─────────────────────────────────────────────────────────────────────────╯

```

## Quick Start

```bash
# default output
cvefind n8n --ecosystem npm
```

```bash
# include GHSA items without CVE + filter by severity + JSON output
cvefind n8n -e npm --include-ghsa-pending --min-severity high -o json
```

```bash
# YAML output
cvefind n8n -e npm -o yaml
```

## CLI Usage

```bash
cvefind [OPTIONS] PACKAGE_NAME
```

### Arguments

- `PACKAGE_NAME`  
  Target package name, e.g. `n8n`

### Options

- `-e, --ecosystem TEXT`  
  Package ecosystem (default: `npm`)  
  Supported: `npm`, `pypi`, `maven`, `nuget`, `go`, `packagist`, `rubygems`, `cargo`

- `-a, --alias TEXT`  
  Extra alias term for fallback searching (repeatable)

- `--include-ghsa-pending`  
  Include GHSA advisories that do not yet have a CVE ID

- `--min-severity [low|medium|moderate|high|critical]`  
  Minimum severity threshold

- `-o, --output [default|json|yaml]`  
  Output format (default: `default`)

- `--timeout FLOAT`  
  HTTP timeout in seconds (default: `20.0`)

## Output Behavior

### `default` output

Block style:

```text
[Critical] CVE-2026-25115 (CVSSv3.1 9.9)
Summary: n8n has a Python sandbox escape
 ⤷ GHSA: https://github.com/advisories/GHSA-...
 ⤷ NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-25115
```

Records are sorted by newest published date first.

### `json` / `yaml` output

Structured output includes:
- `package`, `ecosystem`
- `aliases_used`
- `min_severity`
- `count`
- `cves[]` with:
  - `cve_id`, `severity`
  - `cvss_score`, `cvss_vector`
  - `published_at`, `summary`
  - `sources[]`, `references[]`
- `pending_ghsa[]` (if `--include-ghsa-pending` is enabled)
- `errors` per source

## Environment Variables

- `GITHUB_TOKEN` (recommended)  
  Improves GitHub API rate limits and reliability

- `NVD_API_KEY` (recommended)  
  Improves NVD API rate limits and reliability

## Scope and Limitations

- Focused on CVE discovery and aggregation
- Does not currently perform version impact resolution (affected vs fixed for a specific installed version)
- Source APIs can have sync delays; using multiple sources reduces, but does not eliminate, misses

## Development

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -q
```

Basic syntax check:

```bash
PYTHONPYCACHEPREFIX=/tmp/pycache python3 -m py_compile src/cvefind/*.py tests/test_service.py
```
