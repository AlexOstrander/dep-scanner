# Dependency Vulnerability Scanner

Python-based CLI and web tool that:

- Resolves direct and transitive dependencies from common manifests/lockfiles.
- Queries both OSV.dev and GitHub Security Advisories.
- Produces human-readable console output and a JSON report.
- Supports advisory/package suppression via an ignore file.
- Flags potentially unmaintained packages by release age.

## Supported Inputs

- JavaScript: `package.json` + `package-lock.json` or `yarn.lock`
- Python: `requirements.txt` (optionally with `poetry.lock` or `Pipfile.lock`)
- Additional ecosystem support: Rust (`Cargo.toml` + `Cargo.lock`)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI Usage

```bash
./scanner.py package.json package-lock.json --json-out report.json
./scanner.py requirements.txt poetry.lock --ignore-file ignore-list.json
./scanner.py requirements.txt --months-unmaintained 24
```

## Add it to your ~/.bashrc and run anywhere:

```bash
alias dep-scan='python3 /path/to/your/scanner.py'
source ~/.bashrc
dep-scan --help
dep-scan /path/to/requirements.txt
```

## Web UI (FastAPI)

```bash
./scanner.py --serve --host 127.0.0.1 --port 8000
```

Then open [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Output includes: 

- Vulnerable package name, version, severity, CVE IDs, descriptions, links
- Suggested remediation (first patched versions when available)
- Summary totals and vulnerable percentage

## Ignore List Format

Use JSON shaped like `ignore-list.example.json`:

- `ignore_advisories`: advisory IDs or CVE IDs
- `ignore_packages`: `(ecosystem, name, version)` triplets

## Notes and Edge Cases

- If lockfiles are missing, the scanner attempts best-effort resolution.
- For plain `requirements.txt`, transitive dependencies are resolved from PyPI metadata.
- GitHub advisory API is rate-limited without a token; set `GITHUB_TOKEN` or `--github-token`.

