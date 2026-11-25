# EmberStrike

**Developer: LordXapose**

A research and reporting assistant for **authorized** assessments. It compares service details you already observed with public NVD and CISA Known Exploited Vulnerabilities (KEV) records. Every result is labeled a **possible match**; a banner, product name, or version alone does not establish that a host is vulnerable.

The tool only contacts those public vulnerability-data services. It never connects to, scans, or sends requests to an assessed asset, and it does not generate exploit payloads. Assessment data stays local unless you explicitly save a report. **Stay within your written authorization and scope. No credentials or secrets are needed.**

## Install

Python 3.10 or later is required.

```bash
cd vuln-research-cli
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Alternatively, install dependencies with `python -m pip install -r requirements.txt` and run `python -m vuln_research`.

## Quick start

Start an interactive session:

```bash
emberstrike
```

The interactive terminal opens with the custom EmberStrike ASCII banner you supplied and credits LordXapose. Structured JSON and Markdown output stays free of banner text.

Use dedicated commands for searching and viewing a CVE advisory:

```bash
emberstrike search \
  --assessment "Quarterly internal review" \
  --product "Apache Tomcat" --vendor Apache \
  --observed-version 9.0.80 --confidence High

emberstrike show CVE-2023-42794
```

`search` displays a summary table followed by detailed possible-match evidence. `show` retrieves public CVE/CISA advisory details, affected versions, remediation, and safe verification guidance. It does not provide exploit instructions, payloads, or proof-of-concept links.

Or provide observed details as flags. No target traffic is sent:

```bash
emberstrike \
  --assessment "Quarterly internal review" \
  --scope-notes "Written approval; staging environment only" \
  --asset app-01 \
  --port 8443 --protocol https \
  --service web-server --product "Apache Tomcat" \
  --vendor Apache --observed-version 9.0.80 --build-number "distro package 9.0.80-2" \
  --platform "Ubuntu 22.04" --modules "default configuration" \
  --identified-by "approved asset inventory" --confidence Medium \
  --format markdown --output report.md
```

Choose `--format plain`, `json`, or `markdown`. By default, EmberStrike displays all possible matches it retrieves; use `--limit 25` to cap the list. `--output FILE` saves that format locally and also prints the report. Use `--offline` to skip public-source requests, `--no-color` to disable color, or set `NO_COLOR` in the environment. `--non-interactive` disables prompts; it is useful for scripts. Run `emberstrike --help` for all input flags and examples.

## How to read matches

- **High / Medium / Low** describes how closely the supplied product/vendor/version details match the public record—not certainty about the host.
- Version ranges are compared only when source data provides a range the tool can interpret. Unknown or vendor-specific version formats remain uncertain.
- Build and patch details matter: distributions may backport fixes without changing an upstream version string. Review vendor guidance before drawing conclusions.
- CISA KEV status is shown only when the CVE appears in that catalog. Source outages, rate limits, and offline use are reported without fabricating records.
- Safe verification means checking an approved inventory or vendor-supported, non-invasive method. This tool provides no exploit steps.

## Roadmap

These are planned improvements, not features currently available. The order prioritizes match reliability before adding more data and workflows.

### 1. Match accuracy

- Improve CPE parsing, affected-version range handling, and deduplication.
- Treat unfamiliar or vendor-specific versions conservatively; never infer that an unparseable version is affected.
- Distinguish product match, version match, and host verification, and explain what evidence supports each confidence level.
- Test ambiguous product names, vendor forks, backported fixes, missing versions, and conflicting evidence.

**Milestone:** matches show their supporting evidence and uncertainty, while unsupported matches are filtered or clearly qualified.

### 2. Source reliability and completeness

- Follow NVD pagination so large searches do not silently stop at the first page.
- Add local caching with refresh controls and clear cache age indicators.
- Avoid downloading the full CISA KEV catalog for each individual `show` lookup.
- Distinguish source outages, rate limits, skipped/offline sources, and successful searches.
- Add bounded retries and respect public API guidance.

**Milestone:** a source failure is never presented as evidence that no vulnerabilities exist; cached data can support repeat or offline research.

### 3. Trusted-source evidence

- Expand modular adapters for primary vendor advisories and trusted public catalogs.
- Display available CVSS score/vector, CWE, affected configurations, remediation dates, and fixed versions.
- Attribute each important fact to its source; label unavailable information rather than filling gaps.
- Treat vendor “not affected” and fixed-version statements as evidence to assess, not host-level proof.

**Milestone:** users can trace advisory, version, severity, and exploitation claims to the source that supplied them.

### 4. CLI and reporting workflow

- Improve subcommand help and make option placement consistent (`emberstrike search --help`, `emberstrike show --help`).
- Refine interactive prompts, validation, and input review before lookup.
- Add table sorting/filtering and concise versus detailed display modes.
- Version the JSON report schema and add report timestamps and assessment metadata.
- Keep the custom banner readable in narrow terminals and separate from machine-readable output.

**Milestone:** a new user can run a search, interpret its evidence, and save a report without needing prior CVE expertise.

### 5. Local inventory and assessment workflows

- Support local SBOM or package inventory imports, such as CycloneDX and SPDX, for comparison with public advisories.
- Add optional local case files to save observations and reports without uploading assessment data.
- Compare reports over time to identify newly published or changed advisories.
- Add redacted exports and configurable local retention.

**Milestone:** users can repeat and compare an assessment locally without EmberStrike connecting to assessed assets or transmitting inventory details.

### 6. Packaging and release quality

- Add CI for tests, formatting, type checks, and dependency/security checks.
- Test supported Python versions and Linux, macOS, and Windows terminal behavior.
- Publish versioned releases and document sources, limitations, privacy, and responsible use.
- Include synthetic sample reports clearly labeled as examples.

**Milestone:** fresh installs and documented commands work in CI, and published releases correspond to tested source.

### Recommended implementation order

1. Match accuracy and NVD pagination.
2. Source provenance, caching, and better outage handling.
3. Vendor-source coverage and report improvements.
4. Local inventory/SBOM workflows and release automation.

EmberStrike will remain a research and reporting assistant: no target scanning, exploit payloads, proof-of-concept execution, or instructions for gaining access.

## Development

Run the focused unit tests:

```bash
python -m unittest discover -s tests -v
```
