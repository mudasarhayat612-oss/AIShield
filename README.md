# 🛡️ AIShield — AI Spam, Scam & Phishing Link Detector

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Django](https://img.shields.io/badge/Django-6.1-darkgreen?logo=django)
![scikit--learn](https://img.shields.io/badge/scikit--learn-1.9-orange?logo=scikit-learn)
![Project](https://img.shields.io/badge/Project-Educational-lightgrey)

AIShield is an **AI/ML-powered Django web security application** that analyzes messages and URLs for potential spam, scams, and phishing indicators.

The application combines **Machine Learning + rule-based security analysis** to generate a **0–100% risk score** and classify content as **LOW, MEDIUM, or HIGH risk**.

> 🎓 **Portfolio / Educational Project:** This project demonstrates practical Django, NLP, Machine Learning, URL analysis, database integration, and dashboard development. It is not intended to replace professional security software.

---

## 🚀 Features

### ⭐ Portfolio Highlights

- End-to-end Django + Machine Learning integration
- Hybrid text and URL security analysis
- Persistent detection history with SQLite
- Analytics dashboard with Chart.js
- ML spam/safe classification
- Phishing URL analysis
- Risk scoring from 0–100%
- LOW / MEDIUM / HIGH risk classification
- Detailed detection reports
- Responsive web interface
- Deployment-ready Django configuration
- Portable ML model path

### 🤖 AI Spam Detection

- Machine Learning-based message classification
- Detects spam and safe messages
- Displays ML prediction
- Displays ML confidence percentage
- Uses TF-IDF and Logistic Regression

### 🔗 Phishing URL Detection

AIShield analyzes URLs for:

- IP address-based URLs
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
- `@` symbols

### 📊 Risk Scoring

Every detection receives a score:

```text
0% → 100%