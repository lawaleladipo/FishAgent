#!/usr/bin/env python3
"""
FishAgent — Protocol-First Phishing Triage CLI from Raw RFC-5322 (.eml) Artifacts.

Evaluates cryptographic & envelope mail headers (SPF, DKIM, DMARC, Return-Path / Reply-To
organizational domain alignment), Public-Suffix URL & HTML anchor-mismatch forensics,
MIME attachment smuggling indicators, and bounded temperature=0 LLM intent scoring.
"""

from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import click
from dotenv import load_dotenv
import tldextract

_ENV_FILE = Path(__file__).resolve().parent / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE)

# Offline Public Suffix List extractor (zero outbound network calls during URL triage)
PSL_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

URL_REGEX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)

PROTECTED_BRANDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "outlook": "outlook.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citi.com",
    "okta": "okta.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "stripe": "stripe.com",
}

HIGH_RISK_EXTENSIONS: Set[str] = {
    ".html",
    ".htm",
    ".shtml",
    ".svg",
    ".iso",
    ".img",
    ".vhd",
    ".lnk",
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".one",
    ".docm",
    ".xlsm",
    ".pptm",
}

CREDENTIAL_PATH_TOKENS = ("login", "signin", "verify", "auth", "oauth", "password", "update", "secure", "document")

URGENCY_CUES = (
    "urgent",
    "immediately",
    "immediate action",
    "within 24 hours",
    "within 2 hours",
    "suspended",
    "closed",
    "lockout",
    "avoid suspension",
    "unusual sign-in",
    "verify your",
    "update your credentials",
    "payslip",
    "wire transfer",
)


@dataclass
class URLFinding:
    url: str
    registered_domain: str
    subdomain: str
    suspicious: bool
    reasons: List[str] = field(default_factory=list)
    anchor_text: Optional[str] = None


@dataclass
class AttachmentFinding:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    suspicious: bool
    reasons: List[str] = field(default_factory=list)


@dataclass
class EmailTriageReport:
    file: str
    subject: str
    from_header: str
    return_path: str
    reply_to: str
    header_flags: List[str]
    auth_summary: Dict[str, str]
    url_findings: List[URLFinding]
    attachment_findings: List[AttachmentFinding]
    language_analysis: Dict[str, Any]
    composite_risk_score: int
    verdict: str
    mitre_techniques: List[str]


def registered_domain_of(address_or_host: str) -> str:
    """Extract the registrable apex domain (e.g., 'sub.example.co.uk' -> 'example.co.uk')."""
    if not address_or_host:
        return ""
    candidate = address_or_host.strip().strip("<>")
    if "@" in candidate:
        _, addr = parseaddr(candidate)
        host = addr.split("@")[-1] if "@" in addr else candidate.split("@")[-1]
    else:
        host = candidate
    ext = PSL_EXTRACTOR(host.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host.lower()


def _extract_auth_token(auth_header: str, mechanism: str) -> str:
    match = re.search(rf"\b{mechanism}=([a-zA-Z0-9_-]+)", auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def analyze_headers(msg: EmailMessage) -> Tuple[List[str], Dict[str, str]]:
    """Inspect envelope alignment, Reply-To divergence, and SPF/DKIM/DMARC results."""
    flags: List[str] = []
    from_hdr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    auth_hdr = " ".join(msg.get_all("Authentication-Results", []))

    spf = _extract_auth_token(auth_hdr, "spf")
    dkim = _extract_auth_token(auth_hdr, "dkim")
    dmarc = _extract_auth_token(auth_hdr, "dmarc")

    auth_summary = {"spf": spf, "dkim": dkim, "dmarc": dmarc}

    if spf in ("fail", "softfail"):
        flags.append(f"SPF authentication failed ({spf})")
    if dkim == "fail":
        flags.append("DKIM cryptographic signature failed")
    if dmarc == "fail":
        flags.append("DMARC policy check failed")

    from_apex = registered_domain_of(from_hdr)
    rp_apex = registered_domain_of(return_path)
    reply_apex = registered_domain_of(reply_to)

    # Distinguish true organizational-domain envelope mismatch from benign ESP bounce subdomains
    if from_apex and rp_apex and from_apex != rp_apex:
        if dmarc == "pass" and dkim == "pass":
            flags.append(
                f"Third-party ESP bounce domain ({rp_apex}) aligned via DKIM/DMARC"
            )
        else:
            flags.append(
                f"Envelope Return-Path apex ({rp_apex}) mismatches From apex ({from_apex}) without DMARC pass"
            )

    if from_apex and reply_apex and from_apex != reply_apex:
        flags.append(
            f"Reply-To domain ({reply_apex}) diverges from From domain ({from_apex})"
        )

    return flags, auth_summary


def _detect_brand_impersonation(subdomain: str, domain_label: str, apex: str) -> List[str]:
    reasons: List[str] = []
    clean_domain = re.sub(r"[^a-z0-9]", "", domain_label.lower())
    sub_lower = subdomain.lower()

    for brand, official_apex in PROTECTED_BRANDS.items():
        if apex == official_apex:
            continue
        if brand in sub_lower:
            reasons.append(
                f"Subdomain impersonates '{brand}' while registered apex is '{apex}'"
            )
        elif brand in domain_label.lower():
            reasons.append(
                f"Deceptive brand-stuffed apex '{apex}' impersonating '{official_apex}'"
            )
        else:
            ratio = SequenceMatcher(None, clean_domain, brand).ratio()
            # Catch consonant-dropped lookalikes such as 'bnkofamrica' -> 'bankofamerica'
            trimmed = clean_domain.replace("update", "").replace("secure", "").replace("login", "")
            trimmed_ratio = SequenceMatcher(None, trimmed, brand).ratio() if trimmed else 0.0
            if max(ratio, trimmed_ratio) >= 0.78 and len(brand) >= 6:
                reasons.append(
                    f"Lookalike/typosquat domain '{apex}' resembles '{official_apex}'"
                )

    if any(tok in domain_label.lower() for tok in ("payroll", "helpdesk", "sso", "login")) and (
        any(tok in domain_label.lower() for tok in ("secure", "update", "verify", "portal"))
    ):
        reasons.append(f"High-risk credential-lure naming pattern in domain '{apex}'")

    return reasons


def evaluate_single_url(
    url: str, anchor_text: Optional[str] = None, sender_apex: str = ""
) -> URLFinding:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    ext = PSL_EXTRACTOR(host)
    apex = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    reasons: List[str] = []

    # 1. Raw IP literal check
    try:
        ipaddress.ip_address(host)
        reasons.append(f"URL uses raw IP literal ({host}) instead of a domain name")
    except ValueError:
        pass

    # 2. Punycode / IDN homograph check
    if "xn--" in host:
        reasons.append(f"IDN Punycode homograph indicator detected in '{host}'")

    # 3. Subdomain / typosquat brand impersonation
    reasons.extend(_detect_brand_impersonation(ext.subdomain, ext.domain, apex))

    # 4. Anchor text vs. href domain mismatch (HTML phishing trick)
    if anchor_text and ("http://" in anchor_text.lower() or "https://" in anchor_text.lower()):
        claimed_apex = registered_domain_of(urlparse(anchor_text.strip()).hostname or "")
        if claimed_apex and apex and claimed_apex != apex:
            reasons.append(
                f"HTML anchor text claims '{claimed_apex}' but href points to '{apex}'"
            )

    # 5. Unencrypted HTTP on credential-collection path
    path_lower = (parsed.path or "").lower()
    if parsed.scheme == "http" and any(tok in path_lower for tok in CREDENTIAL_PATH_TOKENS):
        reasons.append("Unencrypted HTTP scheme used on credential/login URL")

    # 6. Unrelated external credential link when sender claims corporate identity
    if (
        sender_apex
        and apex
        and apex != sender_apex
        and any(tok in path_lower for tok in CREDENTIAL_PATH_TOKENS)
        and not reasons
    ):
        reasons.append(
            f"Credential/document action link points to external domain '{apex}' != sender '{sender_apex}'"
        )

    return URLFinding(
        url=url,
        registered_domain=apex,
        subdomain=ext.subdomain,
        suspicious=len(reasons) > 0,
        reasons=reasons,
        anchor_text=anchor_text,
    )


def extract_bodies_and_urls(msg: EmailMessage, sender_apex: str) -> Tuple[str, List[URLFinding]]:
    """Extract both plain and HTML MIME bodies and inspect all embedded URLs + HTML anchors."""
    plain_parts: List[str] = []
    html_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode("utf-8", errors="ignore")
            if ctype == "text/plain" and isinstance(content, str):
                plain_parts.append(content)
            elif ctype == "text/html" and isinstance(content, str):
                html_parts.append(content)
    else:
        ctype = msg.get_content_type()
        content = msg.get_content()
        if ctype == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    seen_urls: Dict[str, URLFinding] = {}

    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("http://", "https://")):
                anchor_label = a.get_text(strip=True) or None
                seen_urls[href] = evaluate_single_url(href, anchor_label, sender_apex)
        if not plain_parts:
            plain_parts.append(soup.get_text(separator=" ", strip=True))

    combined_text = "\n".join(plain_parts).strip()
    for raw_url in URL_REGEX.findall(combined_text):
        cleaned = raw_url.rstrip(".,;)")
        if cleaned not in seen_urls:
            seen_urls[cleaned] = evaluate_single_url(cleaned, None, sender_apex)

    return combined_text, list(seen_urls.values())


def analyze_attachments(msg: EmailMessage) -> List[AttachmentFinding]:
    """Inspect MIME attachments for HTML smuggling, dangerous extensions, and SHA-256 hashes."""
    findings: List[AttachmentFinding] = []
    for part in msg.iter_attachments():
        filename = part.get_filename() or "unnamed_attachment"
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        sha256 = hashlib.sha256(payload).hexdigest()
        reasons: List[str] = []

        lower_name = filename.lower()
        ext = Path(lower_name).suffix
        if ext in HIGH_RISK_EXTENSIONS:
            reasons.append(f"High-risk attachment extension '{ext}' (initial-access / smuggling risk)")

        parts = lower_name.split(".")
        if len(parts) >= 3 and f".{parts[-1]}" in HIGH_RISK_EXTENSIONS:
            reasons.append(f"Double-extension masquerading pattern detected ('{filename}')")

        findings.append(
            AttachmentFinding(
                filename=filename,
                content_type=ctype,
                size_bytes=len(payload),
                sha256=sha256,
                suspicious=len(reasons) > 0,
                reasons=reasons,
            )
        )
    return findings


def _heuristic_language_score(subject: str, text: str) -> Dict[str, Any]:
    corpus = f"{subject}\n{text}".lower()
    matched = [cue for cue in URGENCY_CUES if cue in corpus]
    score = min(len(matched) * 2 + (2 if "!" in subject or subject.isupper() else 0), 10)
    reasoning = (
        f"Matched social-engineering urgency/coercion cues: {', '.join(matched)}"
        if matched
        else "No coercive urgency or credential-harvesting phrasing detected."
    )
    return {
        "score": score,
        "triggers": matched,
        "reasoning": reasoning,
        "mode": "deterministic_fallback",
    }


def score_language_intent(subject: str, text: str, use_llm: bool = True) -> Dict[str, Any]:
    """Score social-engineering manipulation at temperature=0, with deterministic offline fallback."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not use_llm or not api_key:
        return _heuristic_language_score(subject, text)

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        prompt = (
            "You are a senior SOC email security analyst. Evaluate ONLY the social-engineering "
            "and Business Email Compromise (BEC) linguistic risk of the message below on a 0-10 scale.\n"
            "Return strict JSON with keys: score (integer 0-10), triggers (list of short phrases), "
            "and reasoning (1-2 concise sentences).\n\n"
            f"Subject: {subject}\nBody:\n{text[:4000]}"
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            response_format={"type": "json_object"},
        )
        parsed = json.loads(resp.choices[0].message.content or "{}")
        return {
            "score": int(max(0, min(10, int(parsed.get("score", 0))))),
            "triggers": list(parsed.get("triggers", [])),
            "reasoning": str(parsed.get("reasoning", "")),
            "mode": f"openai:{model}",
        }
    except Exception as exc:
        fallback = _heuristic_language_score(subject, text)
        fallback["llm_error"] = str(exc)
        return fallback


def compute_composite_verdict(
    header_flags: List[str],
    auth_summary: Dict[str, str],
    urls: List[URLFinding],
    attachments: List[AttachmentFinding],
    lang_score: int,
) -> Tuple[int, str, List[str]]:
    """Combine cryptographic header evidence, URL math, attachments, and intent score (0-100)."""
    risk = 0
    mitre: Set[str] = set()

    if auth_summary.get("spf") in ("fail", "softfail"):
        risk += 20
        mitre.add("T1656")
    if auth_summary.get("dkim") == "fail":
        risk += 20
        mitre.add("T1656")
    if auth_summary.get("dmarc") == "fail":
        risk += 20
        mitre.add("T1656")

    if any("mismatches From apex" in f or "Reply-To domain" in f for f in header_flags):
        risk += 15
        mitre.add("T1656")

    suspicious_urls = [u for u in urls if u.suspicious]
    if suspicious_urls:
        risk += min(35 + (len(suspicious_urls) - 1) * 10, 45)
        mitre.add("T1566.002")

    suspicious_attachments = [a for a in attachments if a.suspicious]
    if suspicious_attachments:
        risk += 35
        mitre.add("T1566.001")

    risk += int(lang_score * 2.5)
    if lang_score >= 6 and not mitre:
        mitre.add("T1598")

    bounded = min(risk, 100)
    if bounded >= 60:
        verdict = "HIGH_RISK_PHISHING"
    elif bounded >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return bounded, verdict, sorted(mitre)


def analyze_email_file(filepath: str, use_llm: bool = True) -> EmailTriageReport:
    """Parse and triage a single raw .eml artifact end-to-end."""
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = str(msg.get("Subject", "(No Subject)"))
    from_hdr = str(msg.get("From", ""))
    return_path = str(msg.get("Return-Path", ""))
    reply_to = str(msg.get("Reply-To", ""))
    sender_apex = registered_domain_of(from_hdr)

    header_flags, auth_summary = analyze_headers(msg)
    body_text, url_findings = extract_bodies_and_urls(msg, sender_apex)
    attachment_findings = analyze_attachments(msg)
    lang_analysis = score_language_intent(subject, body_text, use_llm=use_llm)

    score, verdict, mitre = compute_composite_verdict(
        header_flags,
        auth_summary,
        url_findings,
        attachment_findings,
        int(lang_analysis.get("score", 0)),
    )

    return EmailTriageReport(
        file=os.path.basename(filepath),
        subject=subject,
        from_header=from_hdr,
        return_path=return_path,
        reply_to=reply_to,
        header_flags=header_flags,
        auth_summary=auth_summary,
        url_findings=url_findings,
        attachment_findings=attachment_findings,
        language_analysis=lang_analysis,
        composite_risk_score=score,
        verdict=verdict,
        mitre_techniques=mitre,
    )


def print_human_report(report: EmailTriageReport) -> None:
    click.echo(f"\n{'=' * 72}")
    click.echo(f"Artifact : {report.file}")
    click.echo(f"Subject  : {report.subject}")
    click.echo(f"From     : {report.from_header}")
    click.echo(
        f"Auth     : SPF={report.auth_summary['spf']} | "
        f"DKIM={report.auth_summary['dkim']} | DMARC={report.auth_summary['dmarc']}"
    )
    click.echo(
        f"Verdict  : {report.verdict} (Composite Risk: {report.composite_risk_score}/100)"
    )
    if report.mitre_techniques:
        click.echo(f"MITRE    : {', '.join(report.mitre_techniques)}")

    if report.header_flags:
        click.echo("\n[Header Forensics]")
        for flag in report.header_flags:
            click.echo(f"  - {flag}")

    if report.url_findings:
        click.echo("\n[URL & Public-Suffix Analysis]")
        for u in report.url_findings:
            tag = "SUSPICIOUS" if u.suspicious else "CLEAN"
            click.echo(f"  - [{tag}] {u.url} (apex: {u.registered_domain})")
            for reason in u.reasons:
                click.echo(f"      * {reason}")

    if report.attachment_findings:
        click.echo("\n[MIME Attachments]")
        for att in report.attachment_findings:
            tag = "SUSPICIOUS" if att.suspicious else "CLEAN"
            click.echo(f"  - [{tag}] {att.filename} ({att.content_type}, sha256={att.sha256[:16]}...)")
            for reason in att.reasons:
                click.echo(f"      * {reason}")

    click.echo("\n[Social-Engineering Intent Analysis]")
    click.echo(
        f"  - Score: {report.language_analysis['score']}/10 "
        f"({report.language_analysis['mode']})"
    )
    click.echo(f"  - Reasoning: {report.language_analysis['reasoning']}")


@click.command()
@click.argument("target", default="samples", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output structured JSON triage report")
@click.option("--no-llm", is_flag=True, help="Force deterministic offline triage without OpenAI API calls")
def main(target: str, as_json: bool, no_llm: bool) -> None:
    """Triage a raw .eml file or a directory of .eml artifacts."""
    target_path = Path(target)
    eml_files = (
        [target_path]
        if target_path.is_file()
        else sorted(target_path.glob("*.eml"))
    )
    if not eml_files:
        raise click.ClickException(f"No .eml artifacts found at '{target}'")

    reports = [analyze_email_file(str(p), use_llm=not no_llm) for p in eml_files]
    if as_json:
        click.echo(json.dumps([asdict(r) for r in reports], indent=2))
    else:
        for r in reports:
            print_human_report(r)


if __name__ == "__main__":
    main()
