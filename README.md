# 🛡️ AIShield — AI Spam, Scam & Phishing Link Detector

AIShield is an AI-powered web security application built with **Django** that analyzes messages and URLs to identify potential spam, scams, and phishing attempts.

The application combines **Machine Learning** with **rule-based security analysis** to generate a risk score from **0–100%** and classify detected content as **LOW, MEDIUM, or HIGH risk**.

---

## 🚀 Features

### 🤖 AI Spam Detection

* Machine Learning-based message classification
* Detects spam and safe messages
* Displays ML prediction
* Displays ML confidence percentage
* Uses TF-IDF and Logistic Regression

### 🔗 Phishing URL Detection

AIShield analyzes URLs for suspicious characteristics including:

* IP address-based URLs
* Suspicious keywords
* HTTP instead of HTTPS
* Very long URLs
* Excessive subdomains
* Suspicious TLDs
* Multiple hyphens
* URL encoding
* Suspicious domain patterns
* Excessive numbers in domains
* Suspicious path structures
* `@` symbols in URLs

### 📊 Risk Scoring

Every detection receives a risk score from:

```text
0% → 100%
```

Risk levels:

```text
LOW       → Lower-risk content
MEDIUM    → Potentially suspicious content
HIGH      → Highly suspicious content
```

### 🧠 Hybrid Detection

AIShield combines:

```text
Machine Learning
       +
Rule-Based Security Analysis
       ↓
Risk Score
       ↓
Risk Level
```

This allows the system to consider both message patterns and security indicators.

### 📜 Detection History

Users can review previous detections including:

* Original message
* Risk score
* Risk level
* Detection status
* Detected URLs
* Matched suspicious keywords
* ML prediction
* ML confidence
* Detection date and time

### 📈 Dashboard

The dashboard provides an overview of detection activity:

* Total detections
* LOW risk detections
* MEDIUM risk detections
* HIGH risk detections
* Risk percentages
* ML spam/safe statistics
* URL detection statistics
* Recent detections
* Daily detection activity chart

### 🔍 Detection Details

Each detection has a dedicated detail page showing:

* Risk score
* Risk level
* Detection status
* Suspicious keywords
* Detected URLs
* URL security analysis
* ML prediction
* ML confidence
* Detection timestamp

---

## 🧠 Machine Learning

AIShield includes a custom spam classification model.

### ML Pipeline

```text
Message
   ↓
Text Preprocessing
   ↓
TF-IDF Vectorization
   ↓
Logistic Regression
   ↓
Spam / Safe Prediction
   ↓
Confidence Score
```

### Model Configuration

The model uses:

* TF-IDF Vectorizer
* English stop-word filtering
* Unigrams and bigrams
* Sublinear TF
* Logistic Regression
* Random state: `42`

The trained model is stored as:

```text
ml/models/spam_model.pkl
```

---

## 📊 Training Dataset

The project currently uses a manually constructed dataset containing:

* 120 example messages
* 60 safe messages
* 60 spam messages

The dataset is located at:

```text
ml/data/messages.csv
```

### Model Test Result

The current test split achieved:

```text
Accuracy: 100%
Test Samples: 24
Correct Predictions: 24
```

> **Note:** This result is based on a small manually constructed dataset and should not be considered production-grade security or a benchmark of real-world performance. A larger, diverse dataset would be required for reliable deployment.

---

## 🔗 URL Security Analysis

AIShield uses rule-based analysis to inspect URLs.

Examples of security indicators include:

```text
IP Address
Suspicious Keywords
HTTP / HTTPS
URL Length
@ Symbol
Hyphens
Subdomains
Suspicious TLD
URL Encoding
Domain Numbers
Suspicious Path
```

The URL analyzer calculates a security score and classifies the URL as:

```text
LOW
MEDIUM
HIGH
```

---

## 🛡️ Detection Flow

The overall detection process works as follows:

```text
User enters message
        ↓
Extract URLs
        ↓
Analyze suspicious keywords
        ↓
Run ML spam detection
        ↓
Analyze URLs
        ↓
Calculate rule-based risk
        ↓
Combine detection results
        ↓
Generate final risk score
        ↓
Classify risk level
        ↓
Save result to database
        ↓
Display detection result
```

---

## 🖥️ Application Pages

### 🏠 Home

Main detection interface where users can enter messages for analysis.

### 📜 History

Displays previously analyzed messages and their detection results.

### 📊 Dashboard

Provides statistical information and visual charts about detection activity.

### 🔎 Detection Detail

Displays complete analysis information for an individual detection.

---

## 🗂️ Project Structure

```text
AIShield/
│
├── config/
│   ├── settings.py
│   ├── urls.py
│   └── ...
│
├── detector/
│   ├── migrations/
│   ├── templates/
│   │   └── detector/
│   │       ├── home.html
│   │       ├── history.html
│   │       ├── dashboard.html
│   │       └── detection_detail.html
│   │
│   ├── models.py
│   ├── urls.py
│   └── views.py
│
├── ml/
│   ├── data/
│   │   └── messages.csv
│   │
│   ├── models/
│   │   └── spam_model.pkl
│   │
│   └── train_model.py
│
├── manage.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🛠️ Technologies Used

### Backend

* Python
* Django

### Machine Learning

* scikit-learn
* pandas
* NumPy
* Joblib

### Database

* SQLite

### Frontend

* HTML
* CSS
* Bootstrap / responsive UI
* JavaScript
* Chart.js

### Development Environment

* Windows
* Laragon
* Visual Studio Code

---

## 📦 Requirements

The project uses:

```text
Django==6.1.1
scikit-learn==1.9.1
pandas==3.0.6
numpy==2.5.3
joblib==1.6.0
```

These dependencies are also available in:

```text
requirements.txt
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/mudasarhayat612-oss/AIShield.git
```

### 2. Open the project

```bash
cd AIShield
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

#### Windows PowerShell

```powershell
venv\Scripts\Activate.ps1
```

#### Windows CMD

```cmd
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run database migrations

```bash
python manage.py migrate
```

### 7. Start the Django development server

```bash
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

---

## 🧪 Example Tests

### Safe Message

```text
Hello, how are you?
```

Expected result:

```text
LOW
```

### Suspicious Message

```text
URGENT! Verify your account immediately.
```

Expected result:

```text
HIGH / suspicious
```

### Spam Message

```text
Congratulations! You won Rs. 50,000. Claim your prize now!
```

Expected result:

```text
SPAM
```

### Suspicious URL

```text
http://example.com/verify-account
```

The URL analyzer checks the URL for suspicious security indicators and generates a risk assessment.

---

## 📊 Dashboard Analytics

AIShield stores detection records in an SQLite database.

The dashboard calculates statistics such as:

```text
Total Detections
LOW Risk
MEDIUM Risk
HIGH Risk
ML Spam
ML Safe
URL Detections
Daily Detection Activity
```

This provides a simple overview of application usage and detection results.

---

## 🔐 Security Approach

AIShield is designed as an **educational and portfolio project** demonstrating:

* Machine Learning integration
* Natural language text classification
* Rule-based security analysis
* URL analysis
* Risk scoring
* Django application development
* Database integration
* Dashboard analytics

It should **not** be treated as a replacement for professional antivirus, anti-phishing, email security, or enterprise security systems.

---

## 🔮 Future Improvements

Possible future improvements include:

* Larger real-world spam datasets
* More advanced NLP models
* Transformer-based classification
* Real-time URL reputation checking
* VirusTotal API integration
* WHOIS/domain-age analysis
* DNS-based analysis
* Browser extension
* User authentication
* Admin panel
* Export detection reports
* PostgreSQL deployment
* Cloud deployment
* REST API
* Automated model retraining
* Improved phishing URL datasets

---

## 🎯 Project Purpose

The purpose of AIShield is to demonstrate how **Artificial Intelligence, Machine Learning, and web security techniques** can be combined in a Django web application.

The project was developed as a practical software engineering and machine learning project.

---

## 👨‍💻 Developer

**Mudasar Hayat**

BS Software Engineering Student

Virtual University of Pakistan

GitHub:

```text
https://github.com/mudasarhayat612-oss
```

AIShield Repository:

```text
https://github.com/mudasarhayat612-oss/AIShield
```

---

## ⭐ Project

If you find this project useful for learning or reference, consider giving the repository a ⭐ on GitHub.

---

## 📌 Disclaimer

AIShield is an educational project intended for demonstration and learning purposes.

Detection results are based on the current machine learning model and rule-based analysis. The system may produce false positives or false negatives and should not be relied upon as the sole security mechanism for real-world systems.
