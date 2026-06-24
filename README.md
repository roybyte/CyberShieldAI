# CyberShield AI

CyberShield AI is a phishing detection tool built using Python and Flask. It analyzes URLs and email addresses to identify potential phishing attempts using multiple security indicators.

## Features

- URL phishing detection
- Email phishing detection
- Brand impersonation detection
- Free email provider detection
- Domain age analysis
- Registrar information lookup
- Country detection
- VirusTotal reputation analysis
- Risk scoring system
- Human-readable explanations for detections

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- VirusTotal API
- WHOIS

## How It Works

CyberShield AI evaluates multiple indicators such as:

- Suspicious keywords
- Newly registered domains
- Fake brand emails
- Free email providers
- VirusTotal detections
- Suspicious TLDs
- Login and credential harvesting patterns

The system calculates a risk score and provides detailed explanations for why a URL or email was flagged.

## Example Detection

Input:

support-paypal@gmail.com

Output:

- Risk Score: 7
- Risk Percentage: 84%
- Possible Fake PayPal Email
- Free Email Provider
- Detailed Explanation

## Installation

Clone the repository:

```bash
git clone https://github.com/roybyte/CyberShieldAI.git
