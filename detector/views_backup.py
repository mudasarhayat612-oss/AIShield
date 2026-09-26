import os
import re
import ipaddress

from urllib.parse import urlparse

import joblib

from django.shortcuts import render

from .models import Detection


# =========================================================
# ML MODEL
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "spam_model.pkl"
)


try:

    spam_model = joblib.load(
        MODEL_PATH
    )

except Exception:

    spam_model = None


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0

    reasons = []

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "confirm",
        "password",
        "bank",
        "wallet",
        "signin",
        "unlock",
    ]

    suspicious_domain_words = [
        "secure",
        "verify",
        "login",
        "account",
        "update",
        "confirm",
        "support",
        "bank",
        "wallet",
    ]

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".download",
        ".zip",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
    ]

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""

    except Exception:

        hostname = ""

    # -----------------------------------------------------
    # IP ADDRESS
    # -----------------------------------------------------

    is_ip = False

    try:

        ipaddress.ip_address(
            hostname
        )

        is_ip = True

        score += 30

        reasons.append(
            "IP address used instead of a normal domain"
        )

    except ValueError:

        pass

    # -----------------------------------------------------
    # SUSPICIOUS URL KEYWORDS
    # -----------------------------------------------------

    found_url_keywords = []

    for keyword in suspicious_keywords:

        if keyword.lower() in url.lower():

            found_url_keywords.append(
                keyword
            )

    if found_url_keywords:

        keyword_score = min(
            len(found_url_keywords) * 10,
            40
        )

        score += keyword_score

        reasons.append(
            "Suspicious keyword(s): "
            + ", ".join(found_url_keywords)
        )

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    if parsed.scheme.lower() != "https":

        score += 10

        reasons.append(
            "HTTP connection instead of HTTPS"
        )

    # -----------------------------------------------------
    # URL LENGTH
    # -----------------------------------------------------

    if len(url) > 150:

        score += 20

        reasons.append(
            "Very long URL"
        )

    elif len(url) > 100:

        score += 15

        reasons.append(
            "Long URL"
        )

    # -----------------------------------------------------
    # @ SYMBOL
    # -----------------------------------------------------

    if "@" in url:

        score += 20

        reasons.append(
            "@ symbol found in URL"
        )

    # -----------------------------------------------------
    # HYPHENS
    # -----------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 5:

        score += 20

        reasons.append(
            "Large number of hyphens in domain"
        )

    elif hyphen_count >= 3:

        score += 10

        reasons.append(
            "Multiple hyphens in domain"
        )

    # -----------------------------------------------------
    # SUBDOMAINS
    # -----------------------------------------------------

    if not is_ip:

        domain_parts = hostname.split(".")

        if len(domain_parts) >= 5:

            score += 20

            reasons.append(
                "Large number of subdomains"
            )

        elif len(domain_parts) == 4:

            score += 10

            reasons.append(
                "Multiple subdomains detected"
            )

    # -----------------------------------------------------
    # SUSPICIOUS DOMAIN WORDS
    # -----------------------------------------------------

    found_domain_words = []

    for word in suspicious_domain_words:

        if word.lower() in hostname.lower():

            found_domain_words.append(
                word
            )

    if found_domain_words:

        domain_score = min(
            len(found_domain_words) * 10,
            30
        )

        score += domain_score

        reasons.append(
            "Suspicious word(s) in domain: "
            + ", ".join(found_domain_words)
        )

    # -----------------------------------------------------
    # SUSPICIOUS TLD
    # -----------------------------------------------------

    for tld in suspicious_tlds:

        if hostname.lower().endswith(tld):

            score += 15

            reasons.append(
                "Suspicious top-level domain: "
                + tld
            )

            break

    # -----------------------------------------------------
    # URL ENCODING
    # -----------------------------------------------------

    if "%" in url:

        score += 5

        reasons.append(
            "Encoded characters found in URL"
        )

    # -----------------------------------------------------
    # DOUBLE SLASH
    # -----------------------------------------------------

    path = parsed.path or ""

    if "//" in path:

        score += 5

        reasons.append(
            "Unusual double slash in URL path"
        )

    # -----------------------------------------------------
    # NUMBERS IN DOMAIN
    # -----------------------------------------------------

    number_count = sum(
        character.isdigit()
        for character in hostname
    )

    if number_count >= 4:

        score += 10

        reasons.append(
            "Large number of digits in domain"
        )

    # -----------------------------------------------------
    # LIMIT SCORE
    # -----------------------------------------------------

    score = min(
        score,
        100
    )

    # -----------------------------------------------------
    # RISK LEVEL
    # -----------------------------------------------------

    if score >= 70:

        risk = "HIGH"

    elif score >= 30:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    # -----------------------------------------------------
    # DEFAULT REASON
    # -----------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious URL indicators detected"
        )

    return {

        "url": url,

        "score": score,

        "risk": risk,

        "reasons": reasons,

    }


# =========================================================
# MESSAGE DETECTION
# =========================================================

def detect_message(message):

    suspicious_keywords = [

        "you won",
        "you have won",
        "congratulations",
        "claim your prize",
        "claim now",
        "free money",
        "urgent",
        "verify your account",
        "verify account",
        "click here",
        "limited time",
        "investment opportunity",
        "send money",
        "otp",
        "password",
        "bank account",
        "credit card",
        "prize",
        "lottery",
        "winner",

    ]

    matched_keywords = []

    lower_message = message.lower()

    for keyword in suspicious_keywords:

        if keyword in lower_message:

            matched_keywords.append(
                keyword
            )

    # -----------------------------------------------------
    # URL EXTRACTION
    # -----------------------------------------------------

    url_pattern = r"(https?://[^\s]+|www\.[^\s]+)"

    urls = re.findall(
        url_pattern,
        message
    )

    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    url_analysis = []

    for url in urls:

        analysis = analyze_url(
            url
        )

        url_analysis.append(
            analysis
        )

    # -----------------------------------------------------
    # RULE SCORE
    # -----------------------------------------------------

    rule_score = 0

    if matched_keywords:

        rule_score += min(
            len(matched_keywords) * 10,
            60
        )

    # Add URL risk
    if url_analysis:

        highest_url_score = max(
            item["score"]
            for item in url_analysis
        )

        rule_score = max(
            rule_score,
            highest_url_score
        )

    rule_score = min(
        rule_score,
        100
    )

    # -----------------------------------------------------
    # MACHINE LEARNING
    # -----------------------------------------------------

    ml_prediction = "safe"

    ml_confidence = 0

    if spam_model is not None:

        try:

            prediction = spam_model.predict(
                [message]
            )[0]

            ml_prediction = str(
                prediction
            ).lower()

            probabilities = spam_model.predict_proba(
                [message]
            )[0]

            ml_confidence = int(
                max(probabilities) * 100
            )

        except Exception:

            ml_prediction = "safe"

            ml_confidence = 0

    # -----------------------------------------------------
    # FINAL SCORE
    # -----------------------------------------------------

    final_score = rule_score

    if ml_prediction in [
        "spam",
        "scam",
        "phishing",
        "1",
        "true",
    ]:

        final_score = max(
            final_score,
            ml_confidence
        )

    final_score = min(
        final_score,
        100
    )

    # -----------------------------------------------------
    # RISK LEVEL
    # -----------------------------------------------------

    if final_score >= 70:

        risk_level = "HIGH"

        status = "High Risk"

    elif final_score >= 30:

        risk_level = "MEDIUM"

        status = "Suspicious"

    else:

        risk_level = "LOW"

        status = "Likely Safe"

    # -----------------------------------------------------
    # RETURN RESULT
    # -----------------------------------------------------

    return {

        "score": final_score,

        "risk_level": risk_level,

        "status": status,

        "urls": urls,

        "matched_keywords": matched_keywords,

        "url_analysis": url_analysis,

        "ml_prediction": ml_prediction,

        "ml_confidence": ml_confidence,

    }


# =========================================================
# HOME
# =========================================================

def home(request):

    result = None

    if request.method == "POST":

        message = request.POST.get(
            "message",
            ""
        ).strip()

        if message:

            result = detect_message(
                message
            )

            Detection.objects.create(

                message=message,

                risk_score=result["score"],

                risk_level=result["risk_level"],

                status=result["status"],

                detected_urls=", ".join(
                    result["urls"]
                ),

                matched_keywords=", ".join(
                    result["matched_keywords"]
                ),

            )

    return render(
        request,
        "detector/home.html",
        {
            "result": result
        }
    )


# =========================================================
# HISTORY
# =========================================================

def history(request):

    detections = Detection.objects.all().order_by(
        "-created_at"
    )

    total_count = detections.count()

    high_count = detections.filter(
        risk_level="HIGH"
    ).count()

    medium_count = detections.filter(
        risk_level="MEDIUM"
    ).count()

    low_count = detections.filter(
        risk_level="LOW"
    ).count()

    return render(
        request,
        "detector/history.html",
        {

            "detections": detections,

            "total_count": total_count,

            "high_count": high_count,

            "medium_count": medium_count,

            "low_count": low_count,

        }
    )


# =========================================================
# DASHBOARD
# =========================================================

def dashboard(request):

    total = Detection.objects.count()

    low = Detection.objects.filter(
        risk_level="LOW"
    ).count()

    medium = Detection.objects.filter(
        risk_level="MEDIUM"
    ).count()

    high = Detection.objects.filter(
        risk_level="HIGH"
    ).count()

    if total > 0:

        low_percentage = round(
            (low / total) * 100
        )

        medium_percentage = round(
            (medium / total) * 100
        )

        high_percentage = round(
            (high / total) * 100
        )

        risky_percentage = round(
            ((medium + high) / total) * 100
        )

    else:

        low_percentage = 0

        medium_percentage = 0

        high_percentage = 0

        risky_percentage = 0

    recent_detections = Detection.objects.all().order_by(
        "-created_at"
    )[:5]

    return render(
        request,
        "detector/dashboard.html",
        {

            "total": total,

            "low": low,

            "medium": medium,

            "high": high,

            "low_percentage": low_percentage,

            "medium_percentage": medium_percentage,

            "high_percentage": high_percentage,

            "risky_percentage": risky_percentage,

            "recent_detections": recent_detections,

        }
    )


# =========================================================
# DETECTION DETAIL
# =========================================================

def detection_detail(request, id):

    detection = Detection.objects.get(
        id=id
    )

    detected_urls = [

        url.strip()

        for url in detection.detected_urls.split(",")

        if url.strip()

    ]

    url_analysis = []

    for url in detected_urls:

        analysis = analyze_url(
            url
        )

        url_analysis.append(
            analysis
        )

    return render(
        request,
        "detector/detection_detail.html",
        {

            "detection": detection,

            "url_analysis": url_analysis,

        }
    )