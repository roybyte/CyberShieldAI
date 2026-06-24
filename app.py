
import re
import whois
import tldextract
import requests
import base64

from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
VT_API_KEY = "9923huiy8r2ud88r8y993e993ru8ru9iihg.env"


@app.route("/")
def home():
    return send_file("index.html")

def check_virustotal(url):
    
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return malicious + suspicious
        return 0
    
    except Exception as e:
        print("VT ERROR =",e)
        return 0

@app.route("/check", methods=["POST"])
def check():
  
    data = request.json
    text = data.get("message", "").lower()
    
    emails  = re.findall(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        text
    )
    print("Email found =", emails)
    
    email_to_check = ""
    
    if emails:
        email_to_check = emails[0]
    
    urls = re.findall(r'https?://[^\s]+', text)
    print("Urls found =", urls)
    
    url_to_check = text
    
    if urls:
        url_to_check = urls[0]
    
    vt_score = 0
    
    if urls:
        vt_score = check_virustotal(url_to_check)

    score = 0
    detected_words = set()
    domain_age = "Unknown"
    
    registrar = "Unknown"
    country = "Unknown"

    # Long URL Check
    if len(text) > 80:
        score += 1
        detected_words.add("long url")

    suspicious_domain_words = [
        "bank",
        "otp",
        "password",
        "click here",
        "verify",
        "urgent",
        "account blocked",
        "winner",
        "prize",
        "free",
        "login",
        "gift",
        "limited offer",
        "update account",
        "claim now",
        "amazon",
        "security",
        "update",
        "secure",
        "paypal",
        "signin",
        "kyc",
        "aadhaar",
        "aadhar",
        "pan",
        "upi",
        "refund",
        "cashback",
        "reward",
        "netbanking",
        "credit card",
        "debit card",
        "sbi",
        "hdfc",
        "icici",
        "axis bank"
    ]

    safe_domains = [
        "google.com",
        "youtube.com",
        "youtu.be",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "amazon.in",
        "wikipedia.org",
        "gov.in"
    ]
    
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]
    
    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".loan",
        ".tk",
        ".gq",
        ".ml"
    ]
    
    brands = [
            "paypal",
            "google",
            "amazon",
            "github",
            "microsoft"
        ]
        

    # General keyword detection
    for word in suspicious_domain_words:
        if word in text:
            score += 1
            detected_words.add(word)  
            
    #OTP detection       
    if re.search(r'\botp\b', text):
        score  += 2
        detected_words.add("OTP request")
        
        urgency_words = [
            "immediately",
            "within 24 hours",
            "act now",
            "expired",
            "suspended",
            "urgent action required"
        ]
        
        for word in urgency_words:
            if word in text:
                score += 2
                detected_words.add("urgency tactic")
            
        

    # URL detection
    if "http://" in text or "https://" in text:
        
        if "@" in text:
            score += 3
            detected_words.add("@ symbol")
            
        if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url_to_check):
            score +=3
            detected_words.add("ip address url")

        if url_to_check.startswith("http://"):
            score += 2
            detected_words.add("not using HTTPS")
            

        try:

            ext = tldextract.extract(url_to_check)
            domain = ext.domain + "." + ext.suffix

            parsed = urlparse(url_to_check)
            host = parsed.netloc.lower()
       
            for brand in  brands:
                if brand in host and not (
                    host == f"{brand}.com" or
                    host == f"www.{brand}.com"
                ):
                    score += 4
                    detected_words.add("Possible brand impersonation")
                    
            for shortener in shorteners:
              if host.endswith(shortener):
                score += 3
                detected_words.add("shortened url") 
            
            for tld in suspicious_tlds:
                if host.endswith(tld):
                    score += 3
                    detected_words.add("Suspicious domain extension (.xyz)")
            
            if host.count("-") >= 2:
                score += 2
                detected_words.add("multiple hyphens")

            print("HOST =", host)
            print("DOMAIN =", domain)

            # Unknown Link Check
            safe = False

            for safe_domain in safe_domains:
                if host == safe_domain or host.endswith("." + safe_domain):
                    safe = True
                    break

            if not safe:
                score += 2
                detected_words.add("unknown link")

            # Trusted Domain Bonu
            for safe_domain in safe_domains:
                if host == safe_domain or host == "www." + safe_domain:
                    score -= 2
                    detected_words.add("trusted domain")
                    print("TRUSTED DOMAIN FOUND")
                    break

            # Subdomain Analysis
            subdomain = ext.subdomain
            print("SUBDOMAIN =", subdomain)

            for word in suspicious_domain_words:
                if word in subdomain:
                    score += 2
                    detected_words.add(word)
                    print("FOUND IN SUBDOMAIN =", word)
                    print("SCORE =", score)

            # WHOIS Check
            info = whois.whois(domain)
            
            creation = info.creation_date
            registrar = info.registrar
            country = info.country

            if creation:

                if isinstance(creation, list):
                    creation = creation[0]

                age_days = (datetime.now() - creation).days
                domain_age = str(creation.date())

                if age_days < 30:
                    score += 3
                    detected_words.add("New domain(<30 days)")

                elif age_days < 180:
                    score += 2
                    detected_words.add("recent domain (<180 days)")

        except Exception as e:
            print("WHOIS ERROR =", e)
            domain_age = "Could not fetch"
            
    # Email Domain Analysis
    if emails:
        email_username = email_to_check.split("@")[0]
        email_domain = email_to_check.split("@")[1]
        
        free_providers = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com"
        ]
        
        if email_domain in free_providers:
            score += 2
            detected_words.add("free email provider")
            
            
        for brand in brands:
            if brand.lower() in email_username.lower():
                
                if email_domain in free_providers:
                    score += 4
                    detected_words.add(f"Possible fake {brand} email")
        
        suspicious_email_words = [
            "secure",
            "verify",
            "support",
            "account",
            "update",
            "billing",
            "payment",
            "security",
            "login",
            "verification",
            "customer-service"
        ]
        
        for word in suspicious_email_words:
            if word in email_domain:
                score += 2
                detected_words.add(f"Suspicious email domain contains '{word}'")
                
        for brand in brands:
            
            if brand in email_domain:
                valid_domains = [f"{brand}.com"]
                
                if not any(
                    email_domain.endswith(v)
                    for v in valid_domains
                ):
                    score += 4
                    detected_words.add(f"Possible fake {brand} email")

    if vt_score > 0:
        score += min(vt_score, 5)
        detected_words.add(f"VirusTotal flagged by {vt_score} security engines")
        
    score = max(score, 0)

    print("FINAL SCORE =", score)

    if score <= 2:
        result = "Safe"
    elif score <= 6:
        result = "Suspicious"
    else:
        result = "Potential Phishing"    

    risk_percent = min(score * 12, 100)
    
    raw_indicators = list(detected_words)
    
    reasons = []

    if "Possible fake paypal email" in detected_words:
        reasons.append(
            "This email pretends to represent PayPal while using a free email provider."
        )

    if "free email provider" in detected_words:
        reasons.append(
            "Legitimate companies usually do not use free email services for official communication."
        )

    return jsonify({
        "result": result,
        "risk_score": score,
        "risk_percent": risk_percent,
        "virustotal_score": vt_score,
        "detected_words": list(detected_words),
        "domain_age": domain_age,
        "registrar": registrar,
        "country": country,
        "explanation": reasons,
        "raw_indicators": list(detected_words)
    })


if __name__ == "__main__":
    app.run(debug=True)
