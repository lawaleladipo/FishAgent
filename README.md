# FishAgent
FishAgent: AI-Powered Phishing Detection from Raw Emails
# 🎣 FishAgent: AI-Powered Phishing Detection from Raw Emails

FishAgent is a lightweight AI tool designed to help cybersecurity analysts and email investigators detect phishing attempts from raw `.eml` files. It leverages email header analysis, URL inspection, and OpenAI’s GPT model to provide explainable phishing risk assessments.

---

## 📦 Features

- Parse and scan raw `.eml` files from email inboxes
- Analyse SPF, DKIM, and DMARC results
- Detect spoofed domains and impersonation attempts
- Extract and inspect embedded URLs for phishing indicators
- Use OpenAI's GPT model to score the email with a natural language explanation
- CLI interface for investigators and blue teams

---

## 🧠 Why FishAgent?

Phishing remains one of the top attack vectors in enterprise breaches. Analysts often encounter `.eml` files in SOC or DFIR workflows. FishAgent speeds up triage with AI-enhanced insights grounded in real technical signals.

---

## 🚀 Quickstart

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/FishAgentDemo.git
cd FishAgentDemo
