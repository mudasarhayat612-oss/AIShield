# 🛡️ AIShield — AI Spam, Scam & Phishing Link Detector

AIShield is an AI-powered web security application built with Django that analyzes messages and URLs to identify potential spam, scams, and phishing attempts.

The system combines Machine Learning with rule-based security analysis to generate a risk score from 0–100% and classify detected content as LOW, MEDIUM, or HIGH risk.

---

## 🚀 Features

### 🤖 AI Spam Detection

- Machine Learning based message classification
- Detects spam and safe messages
- Displays ML prediction
- Displays ML confidence percentage

### 🔗 Phishing URL Detection

AIShield analyzes URLs for suspicious characteristics such as:

- IP address based URLs
- Suspicious keywords
- HTTP instead of HTTPS
- Very long URLs
- Excessive subdomains
- Suspicious TLDs
- Multiple hyphens
- URL encoding
- Suspicious domain patterns
- Excessive numbers in domains
- Suspicious path structures

### 📊 Risk Scoring

Every detection receives a score from:

```text
0% → 100%