# Dependency Vulnerability Scanner

Python-based CLI and web tool that:

- Resolves direct and transitive dependencies from common manifests/lockfiles.
- Queries both OSV.dev and GitHub Security Advisories.
- Produces human-readable console output and a JSON report.
- Supports advisory/package suppression via an ignore file.
- Flags potentially unmaintained packages by release age (per-ecosystem registry timestamps: PyPI, npm, crates.io, Packagist, Go proxy, RubyGems, NuGet, pub.dev, Hex, Maven Central, and GitHub Actions release dates where applicable; Swift SPM pins are skipped when no reliable timestamp exists).

## Supported Inputs

Manifest / lock pairs are resolved using **OSV.dev ecosystem names** so batch queries match advisory data; **GitHub Security Advisories** are queried for every ecosystem [supported by the global advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories) (`rubygems`, `npm`, `pip`, `maven`, `nuget`, `composer`, `go`, `rust`, `erlang`, `actions`, `pub`, `swift`). The GitHub enum `other` has no single lockfile format and is not ingested here.

- **JavaScript:** `package.json` + `package-lock.json` or `yarn.lock`
- **Python:** `requirements.txt` (optionally with `poetry.lock`, `Pipfile.lock`, or `uv.lock`)
- **Rust:** `Cargo.toml` + `Cargo.lock`
- **Go:** `go.mod` + `go.sum`
- **PHP (Composer):** `composer.json` + `composer.lock`
- **Ruby (Bundler):** `Gemfile` (optional, for direct marking) + `Gemfile.lock`
- **Dart / Flutter (pub):** `pubspec.yaml` (optional) + `pubspec.lock`
- **Elixir (Hex):** `mix.exs` (optional) + `mix.lock`
- **.NET (NuGet):** `packages.lock.json` and/or `*.csproj` (`PackageReference`)
- **Java (Maven):** `pom.xml` (declared versions only; no `${property}` expansion)
- **Swift (SPM):** `Package.swift` (optional, for direct marking) + `Package.resolved`
- **GitHub Actions:** any `.yml` / `.yaml` under `.github/workflows/` (pinned `uses:` refs)

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
./scanner.py requirements.txt uv.lock --show-outdated-upgrade-options
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
- **`go.mod` without `go.sum`:** direct `require` lines (non-indirect) are scanned with the version written in the file; transitives from `go.sum` are not available.
- **`Cargo.toml` without `Cargo.lock`:** not scanned (versions are often ranges; add `Cargo.lock` for pinned crates).
- **Duplicate basenames:** if you pass two paths whose filenames match case-insensitively (e.g. two `package.json` files), the **first** path wins and a warning lists the skipped path.
- GitHub advisory API is rate-limited without a token; set `GITHUB_TOKEN` or `--github-token`.

