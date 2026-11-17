# FishAgent — Protocol-First Phishing Triage from Raw `.eml` Artifacts

[![CI](https://github.com/lawaleladipo/FishAgent/actions/workflows/ci.yml/badge.svg)](https://github.com/lawaleladipo/FishAgent/actions)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**FishAgent** is an explainable phishing forensics CLI built for SOC analysts and DFIR investigators. Instead of pasting rendered email body text into a chatbot, FishAgent parses raw binary RFC-5322 `.eml` artifacts—verifying **cryptographic authentication (`SPF`, `DKIM`, `DMARC`)**, **organizational domain alignment**, **Public-Suffix URL & HTML anchor mismatches**, and **MIME attachment smuggling** *before* consulting a `temperature=0` language model for social-engineering intent.

---

## Architecture

```text
+-----------------------------------+
|      Raw Binary .eml Artifact     |
|   (RFC-5322 Headers + MIME Tree)  |
+-----------------+-----------------+
                  |
                  v
+--------------------------------------------------------+
| Stage 1: Cryptographic & Envelope Header Forensics     |
| - SPF / DKIM / DMARC Parsing (Authentication-Results)  |
| - From vs. Return-Path Apex Alignment (ESP-Aware)      |
| - Reply-To Domain Divergence (BEC Hijack Detection)    |
+-----------------+--------------------------------------+
                  |
                  v
+--------------------------------------------------------+
| Stage 2: Public-Suffix URL, HTML Anchor & MIME Checks  |
| - Offline Mozilla PSL Decomposition (tldextract)       |
| - Subdomain Brand Spoofing & Typosquat Lookalikes      |
| - HTML <a href> vs. Visible Anchor Domain Mismatch     |
| - Punycode (xn--) + Attachment Smuggling (.html/.lnk)  |
+-----------------+--------------------------------------+
                  |
                  v
+--------------------------------------------------------+
| Stage 3: Bounded Intent Scoring (temperature=0)        |
| - OpenAI Structured JSON Scoring OR Offline Fallback   |
+-----------------+--------------------------------------+
                  |
                  v
+--------------------------------------------------------+
| Composite Risk Score (0-100) + MITRE ATT&CK Verdict    |
| (CLEAN / SUSPICIOUS / HIGH_RISK_PHISHING)              |
+--------------------------------------------------------+
```

---

## Key Capabilities

- **ESP-Aware Envelope & Cryptographic Checks:** Distinguishes real sender spoofing (`Return-Path` apex mismatch with failed `DMARC`) from legitimate third-party mailers (SendGrid/SES bounce subdomains passing `DKIM` + `DMARC`), and flags `Reply-To` domain divergence.
- **Public-Suffix & Lookalike Domain Math:** Uses an offline Public Suffix List snapshot (`tldextract`) to catch subdomain brand stuffing (`paypal.com.account-verify.net`), hyphenated brand lures (`secure-paypal-login.com`), consonant-dropped typosquats (`bnkofamrica.com`), Punycode (`xn--`), and raw IP URLs.
- **HTML MIME Anchor-Mismatch & Attachment Smuggling:** Parses `text/html` `<a href>` tags to catch links claiming one domain in visible text while navigating to another, and hashes/flags dangerous attachments (`.html`, `.iso`, `.lnk`, `.one`, `.docm`, double extensions).
- **Reproducible `temperature=0` Intent Scoring + Air-Gapped Mode:** Runs `gpt-4o-mini` (or any configured `OPENAI_MODEL`) at `temperature=0` for consistent BEC/urgency explanations, and runs **100% offline** with `--no-llm` (or whenever `OPENAI_API_KEY` is unset).

---

## Quick Start

```bash
git clone https://github.com/lawaleladipo/FishAgent.git
cd FishAgent
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env  # Optional: add OPENAI_API_KEY
```

### Usage

```bash
# Triage the entire bundled .eml test corpus (Safe1, Safe2_legit_esp, fish1..fish4) offline
.venv/bin/python fishagent.py samples/ --no-llm

# Triage a single .eml artifact and emit structured JSON for SIEM/SOAR ingestion
.venv/bin/python fishagent.py samples/fish4_html_anchor_spoof.eml --json
```

---

## Running Tests & Linter

```bash
.venv/bin/pytest -q
.venv/bin/flake8 fishagent.py tests/ --max-line-length=120
```

## License

Built by **Olawale Oladipo** ([GitHub](https://github.com/lawaleladipo) · [Medium](https://medium.com/@lawaleladipo) · [LinkedIn](https://www.linkedin.com/in/olawale-oladipo-cybersecurity/)).  
Released under the [MIT License](LICENSE).
