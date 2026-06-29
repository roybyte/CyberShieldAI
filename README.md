CyberShield AI

AI-powered phishing detection platform that analyzes URLs and emails using WHOIS intelligence, VirusTotal reputation data, and custom security heuristics.

Live Demo

Try the project here:

https://roybyte.github.io/CyberShieldAI/

---

Overview

CyberShield AI is a phishing detection web application built using Python and Flask. It helps identify malicious URLs and phishing emails by combining multiple security indicators such as WHOIS information, VirusTotal reputation analysis, domain intelligence, and rule-based detection.

The application calculates a risk score, assigns a threat level, and explains exactly why a URL or email has been flagged.

---

Features

- Real-time URL phishing analysis
- Email phishing detection
- Brand impersonation detection
- Free email provider detection
- Domain age verification
- Registrar lookup
- Country detection
- VirusTotal reputation analysis
- Suspicious domain extension detection
- Risk scoring engine
- Human-readable threat explanations

---

Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- VirusTotal API
- WHOIS

---

How It Works

CyberShield AI analyzes multiple indicators, including:

- Suspicious keywords
- Newly registered domains
- Fake brand emails
- Free email providers
- VirusTotal detections
- Suspicious TLDs
- Login and credential harvesting patterns
- Brand impersonation attempts

The system combines these indicators into a risk score and generates an explanation describing why the content is considered suspicious.

---

Example Detection

Input

support-paypal@gmail.com

Output

- Risk Score: 7
- Risk Percentage: 84%
- Possible Fake PayPal Email
- Free Email Provider

Why Flagged

- This email pretends to represent PayPal while using a free email provider.
- Legitimate companies usually do not use free email services for official communication.

---

Screenshots

URL Analysis

Place your screenshot here:

screenshots/url-analysis.png

Email Analysis

Place your screenshot here:

screenshots/email-analysis.png

---

Installation

Clone the repository

git clone https://github.com/roybyte/CyberShieldAI.git

Move into the project directory

cd CyberShieldAI

Install dependencies

pip install -r requirements.txt

Run the application

python app.py

Open

http://127.0.0.1:5000

---

Future Improvements

- Machine Learning based phishing detection
- Email header analysis
- QR code phishing detection
- Threat intelligence feeds
- Detection history
- User authentication
- Dashboard and analytics

---

Author

Ankit Roy

BCA Student | Cybersecurity Enthusiast | Cloud Security Learner

GitHub: https://github.com/roybyte
