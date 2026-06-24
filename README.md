# CyberShield AI

AI-powered phishing detection platform that analyzes URLs and emails using WHOIS intelligence, VirusTotal reputation data, and custom security heuristics.

## Overview

CyberShield AI is a security-focused web application built using Python and Flask. It helps users identify potentially malicious URLs and phishing emails by combining domain intelligence, reputation analysis, and rule-based threat detection techniques.

The system analyzes multiple indicators and generates a risk score along with detailed explanations describing why a URL or email has been flagged.

---

## Features

- Real-time URL phishing analysis
- Email phishing detection
- Brand impersonation detection
- Free email provider detection
- Domain age verification
- Registrar lookup
- Country lookup
- VirusTotal reputation analysis
- Suspicious TLD detection
- Risk scoring engine
- Detailed threat explanations
- Human-readable security reports

---

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- VirusTotal API
- WHOIS

---

## How It Works

CyberShield AI evaluates multiple indicators such as:

- Suspicious keywords
- Newly registered domains
- Fake brand emails
- Free email providers
- VirusTotal detections
- Suspicious domain extensions
- Login and credential harvesting patterns
- Brand impersonation attempts

The system calculates a risk score and provides detailed explanations for why a URL or email was flagged.

---

## Example Detection

### Input

```
support-paypal@gmail.com
```

### Output

- Risk Score: 7
- Risk Percentage: 84%
- Possible Fake PayPal Email
- Free Email Provider
- Detailed Explanation

### Why Flagged

- This email pretends to represent PayPal while using a free email provider.
- Legitimate companies usually do not use free email services for official communication.

---

## Screenshots

### URL Analysis

![URL Analysis](screenshots/url-analysis.png)

### Email Analysis

![Email Analysis](screenshots/email-analysis.png)

---

## Installation

### Clone the repository

```bash
git clone https://github.com/roybyte/CyberShieldAI.git
```

### Move into the project directory

```bash
cd CyberShieldAI
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python app.py
```

### Open in browser

```text
http://127.0.0.1:5000
```

---

## Future Improvements

- Machine Learning based phishing detection
- Email header analysis
- QR code phishing detection
- Real-time threat intelligence feeds
- User authentication and dashboard
- SOC analyst reporting dashboard
- Detection history and analytics

---

## Author

**Ankit Roy**

BCA Student | Cybersecurity Enthusiast | Cloud Security Learner

GitHub: https://github.com/roybyte
