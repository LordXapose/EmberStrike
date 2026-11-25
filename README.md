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

## Development

Run the focused unit tests:

```bash
python -m unittest discover -s tests -v
```
