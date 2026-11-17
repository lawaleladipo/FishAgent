from pathlib import Path
from email.message import EmailMessage

from fishagent import (
    analyze_email_file,
    evaluate_single_url,
    registered_domain_of,
)

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_clean_samples_score_clean():
    safe1 = analyze_email_file(str(SAMPLES_DIR / "Safe1.eml"), use_llm=False)
    assert safe1.verdict == "CLEAN"
    assert safe1.composite_risk_score < 30

    safe2 = analyze_email_file(str(SAMPLES_DIR / "Safe2_legit_esp.eml"), use_llm=False)
    assert safe2.verdict == "CLEAN"
    assert any("aligned via DKIM/DMARC" in f for f in safe2.header_flags)


def test_phishing_samples_flagged_accurately():
    for fname in ("fish1.eml", "fish2.eml", "fish3.eml", "fish4_html_anchor_spoof.eml"):
        report = analyze_email_file(str(SAMPLES_DIR / fname), use_llm=False)
        assert report.verdict in ("SUSPICIOUS", "HIGH_RISK_PHISHING"), f"Missed {fname}"
        assert any(u.suspicious for u in report.url_findings), f"URL missed on {fname}"


def test_html_anchor_mismatch_and_subdomain_spoofing():
    finding = evaluate_single_url(
        "http://paypal.com.account-verify.net/login",
        anchor_text="https://www.paypal.com/signin",
        sender_apex="paypal.com",
    )
    assert finding.suspicious
    assert finding.registered_domain == "account-verify.net"
    assert any("Subdomain impersonates 'paypal'" in r for r in finding.reasons)
    assert any("HTML anchor text claims 'paypal.com'" in r for r in finding.reasons)


def test_dangerous_attachment_smuggling_detected(tmp_path):
    msg = EmailMessage()
    msg["From"] = "HR Desk <hr@example.org>"
    msg["Subject"] = "Updated Compensation Statement"
    msg["Authentication-Results"] = "spf=pass dkim=pass dmarc=pass"
    msg.set_content("Please open your attached compensation statement.")
    msg.add_attachment(
        b"<html><script>window.location='https://evil.example/harvest'</script></html>",
        maintype="text",
        subtype="html",
        filename="Compensation_Q4.pdf.html",
    )
    eml_path = tmp_path / "smuggle.eml"
    eml_path.write_bytes(bytes(msg))

    report = analyze_email_file(str(eml_path), use_llm=False)
    assert len(report.attachment_findings) == 1
    assert report.attachment_findings[0].suspicious
    assert "T1566.001" in report.mitre_techniques


def test_registered_domain_extraction():
    assert registered_domain_of("Support <help@sub.portal.co.uk>") == "portal.co.uk"
