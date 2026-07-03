# DrupEnum

DrupEnum is a small CLI tool for authorized Drupal audits. It enumerates
exposed modules through public `.info.yml` / `.info` files and can optionally
check OSV advisories for detected versions.

## Why DrupEnum

We built DrupEnum because we could not find a lightweight tool that reliably combined Drupal module enumeration, core fingerprinting and vulnerability lookups in one CLI.  More information on https://hdwsec.fr/fr/blog/drupenum-tool/.

## Features

- Enumerate exposed Drupal modules.
- Detect Drupal core from public core/changelog files.
- Estimate Drupal core from packaged static-file fingerprints.
- Flag exposed `services.yml`, `settings.yml`, and `settings.php`-like files.
- Query OSV for matching vulnerabilities and advisory history.
- Print readable text output or JSON.

## How it works

DrupEnum starts from a candidate list of Drupal project names stored in the
packaged `drupal_modules.sqlite` cache. For each candidate, it probes common
public module metadata paths such as:

- `modules/contrib/<module>/<module>.info.yml`
- `modules/<module>/<module>.info.yml`
- `profiles/contrib/<module>/<module>.info.yml`
- `sites/all/modules/.../<module>.info`

When one of those files is reachable and looks like a Drupal `.info.yml` or
classic `.info` file, DrupEnum records the module name, exposed version, Drupal
core requirement, and path.

Core detection uses three signals:

- direct version strings from public core/changelog files;
- exposed config-like files under `sites/default/`;
- optional static-file fingerprinting with `--fingerprint-core`.

Fingerprinting downloads a small set of stable Drupal core assets, hashes them,
and compares those hashes with `drupal_core_hashes.sqlite`. If several Drupal
versions match the same files, results are ranked by match count.

With `--check-vulns`, DrupEnum queries OSV using the Packagist package names
`drupal/core` and `drupal/<module>`. Exact version matches are shown
separately from broader package advisory history.

## Installation

```bash
uv venv
uv pip install .
```

Without `uv`:

```bash
python3 -m pip install .
```

## Usage

Scan a target:

```bash
uv run drupenum https://example.org
```

Fingerprint Drupal core with the packaged hash database:

```bash
uv run drupenum https://example.org --fingerprint-core
```

Check OSV advisories:

```bash
uv run drupenum https://example.org --check-vulns
```

Write JSON output:

```bash
uv run drupenum https://example.org --json -o results.json
```

Use a custom module list or cache:

```bash
uv run drupenum https://example.org --modules-file modules.txt
uv run drupenum https://example.org --db modules.sqlite
```

Control colors:

```bash
uv run drupenum https://example.org --color always
uv run drupenum https://example.org --no-color
```

`NO_COLOR` is respected. Progress logs are written to stderr, so JSON output
on stdout stays parseable.

## Data

DrupEnum ships with packaged SQLite caches:

- `drupenum/data/drupal_modules.sqlite`
- `drupenum/data/drupal_core_hashes.sqlite`

Only scan targets you are authorized to test.
