import whois
import tldextract

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return send_file("index.html")


@app.route("/check", methods=["POST"])
def check():

    data = request.json
    text = data.get("message", "").lower()

    suspicious_words = [
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
        "claim now"
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

    score = 0
    detected_words = []
    domain_age = "Unknown"

    # Keyword Detection
    for word in suspicious_words:
        if word in text:
            score += 1
            detected_words.append(word)

    # Link Detection
    if "http://" in text or "https://" in text:

        safe = False

        for domain in safe_domains:
            if domain in text:
                safe = True
                break

        if not safe:
            score += 2
            detected_words.append("unknown link")

        try:
            ext = tldextract.extract(text)

            domain = ext.domain + "." + ext.suffix

            info = whois.whois(domain)

            creation = info.creation_date

            if creation:

                if isinstance(creation, list):
                    creation = creation[0]

                domain_age = str(creation.date())

        except Exception:
            domain_age = "Could not fetch"

    result = "Potential Phishing" if score >= 2 else "Safe"

    risk_percent = min(score * 15, 100)

    return jsonify({
        "result": result,
        "risk_score": score,
        "risk_percent": risk_percent,
        "detected_words": detected_words,
        "domain_age": domain_age
    })


if __name__ == "__main__":
    app.run(debug=True)