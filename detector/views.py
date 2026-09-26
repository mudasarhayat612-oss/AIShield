import os
import re
import ipaddress

from urllib.parse import urlparse

import joblib

from django.shortcuts import render
from django.db.models import Count
from django.db.models.functions import TruncDate

from .models import Detection


# ============================================================
# MACHINE LEARNING MODEL
# ============================================================

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


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    score = 0

    reasons = []

    suspicious_url_keywords = [

        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "signin",
        "bank",
        "payment",
        "wallet",
        "bonus",
        "reward",
        "claim",
        "free",
        "prize",
        "crypto",
        "bitcoin",
        "investment",
        "recover",
        "unlock",
        "security",
        "support"

    ]

    suspicious_domains = [

        "paypal",
        "apple",
        "microsoft",
        "google",
        "facebook",
        "instagram",
        "amazon",
        "netflix",
        "bank",
        "wallet",
        "crypto"

    ]

    suspicious_tlds = [

        ".xyz",
        ".top",
        ".click",
        ".loan",
        ".work",
        ".download",
        ".win",
        ".buzz",
        ".monster"

    ]


    # --------------------------------------------------------
    # PARSE URL
    # --------------------------------------------------------

    try:

        parsed = urlparse(
            url if "://" in url else "http://" + url
        )

        hostname = parsed.hostname or ""

        path = parsed.path or ""

    except Exception:

        hostname = ""

        path = ""


    hostname_lower = hostname.lower()

    url_lower = url.lower()


    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(
            hostname
        )

        score += 30

        reasons.append(
            "URL uses an IP address instead of a normal domain"
        )

    except ValueError:

        pass


    # --------------------------------------------------------
    # SUSPICIOUS URL KEYWORDS
    # --------------------------------------------------------

    matched_url_keywords = []

    for keyword in suspicious_url_keywords:

        if keyword in url_lower:

            matched_url_keywords.append(
                keyword
            )


    if matched_url_keywords:

        keyword_score = min(
            len(matched_url_keywords) * 10,
            40
        )

        score += keyword_score

        reasons.append(
            "Suspicious URL keywords: "
            + ", ".join(
                matched_url_keywords
            )
        )


    # --------------------------------------------------------
    # HTTP INSTEAD OF HTTPS
    # --------------------------------------------------------

    if url_lower.startswith("http://"):

        score += 10

        reasons.append(
            "URL does not use HTTPS"
        )


    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        score += 20

        reasons.append(
            "URL contains @ symbol"
        )


    # --------------------------------------------------------
    # HYPHENS
    # --------------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 5:

        score += 20

        reasons.append(
            "Domain contains many hyphens"
        )

    elif hyphen_count >= 3:

        score += 10

        reasons.append(
            "Domain contains multiple hyphens"
        )


    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    if hostname:

        try:

            ipaddress.ip_address(
                hostname
            )

            is_ip = True

        except ValueError:

            is_ip = False


        if not is_ip:

            parts = hostname.split(".")

            subdomain_count = max(
                len(parts) - 2,
                0
            )

            if subdomain_count >= 5:

                score += 20

                reasons.append(
                    "URL contains many subdomains"
                )

            elif subdomain_count == 4:

                score += 10

                reasons.append(
                    "URL contains multiple subdomains"
                )


    # --------------------------------------------------------
    # SUSPICIOUS DOMAIN WORDS
    # --------------------------------------------------------

    matched_domains = []

    for domain_word in suspicious_domains:

        if domain_word in hostname_lower:

            matched_domains.append(
                domain_word
            )


    if matched_domains:

        score += min(
            len(matched_domains) * 15,
            30
        )

        reasons.append(
            "Domain contains brand or financial-related words: "
            + ", ".join(
                matched_domains
            )
        )


    # --------------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------------

    for tld in suspicious_tlds:

        if hostname_lower.endswith(tld):

            score += 15

            reasons.append(
                "Suspicious or commonly abused TLD: "
                + tld
            )

            break


    # --------------------------------------------------------
    # URL ENCODING
    # --------------------------------------------------------

    if "%" in url:

        score += 5

        reasons.append(
            "URL contains encoded characters"
        )


    # --------------------------------------------------------
    # DOUBLE SLASH IN PATH
    # --------------------------------------------------------

    if "//" in path:

        score += 5

        reasons.append(
            "URL path contains unusual double slash"
        )


    # --------------------------------------------------------
    # MANY NUMBERS IN DOMAIN
    # --------------------------------------------------------

    if hostname:

        number_count = len(
            re.findall(
                r"\d",
                hostname
            )
        )

        if number_count >= 4:

            score += 10

            reasons.append(
                "Domain contains many numbers"
            )


    # --------------------------------------------------------
    # CAP SCORE
    # --------------------------------------------------------

    score = min(
        score,
        100
    )


    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score >= 70:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # --------------------------------------------------------
    # DEFAULT MESSAGE
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious URL indicators detected"
        )


    return {

        "url": url,

        "score": score,

        "risk_level": risk_level,

        "reasons": reasons

    }


# ============================================================
# MESSAGE DETECTION
# ============================================================

def detect_message(message):

    message_lower = message.lower()


    # --------------------------------------------------------
    # SUSPICIOUS MESSAGE KEYWORDS
    # --------------------------------------------------------

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
        "winner"

    ]


    matched_keywords = []


    for keyword in suspicious_keywords:

        if keyword in message_lower:

            matched_keywords.append(
                keyword
            )


    # --------------------------------------------------------
    # MESSAGE RULE SCORE
    # --------------------------------------------------------

    message_score = min(
        len(matched_keywords) * 10,
        60
    )


    # --------------------------------------------------------
    # URL EXTRACTION
    # --------------------------------------------------------

    url_pattern = (
        r"(https?://[^\s]+|www\.[^\s]+)"
    )

    detected_urls = re.findall(
        url_pattern,
        message
    )


    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    url_analysis = []


    for url in detected_urls:

        analysis = analyze_url(
            url
        )

        url_analysis.append(
            analysis
        )


    # --------------------------------------------------------
    # HIGHEST URL SCORE
    # --------------------------------------------------------

    highest_url_score = 0


    if url_analysis:

        highest_url_score = max(
            item["score"]
            for item in url_analysis
        )


    # --------------------------------------------------------
    # INITIAL RULE SCORE
    # --------------------------------------------------------

    rule_score = max(
        message_score,
        highest_url_score
    )


    # --------------------------------------------------------
    # MACHINE LEARNING
    # --------------------------------------------------------

    ml_prediction = "unavailable"

    ml_confidence = 0

    ml_contribution = 0


    if spam_model is not None:

        try:

            prediction = spam_model.predict(
                [message]
            )[0]


            ml_prediction = str(
                prediction
            ).lower()


            if hasattr(
                spam_model,
                "predict_proba"
            ):

                probabilities = (
                    spam_model.predict_proba(
                        [message]
                    )[0]
                )

                classes = spam_model.classes_


                for index, label in enumerate(
                    classes
                ):

                    if str(label).lower() == "spam":

                        spam_probability = (
                            probabilities[index]
                        )

                        ml_confidence = round(
                            spam_probability * 100
                        )

                        break


            if ml_prediction == "spam":

                ml_contribution = round(
                    ml_confidence * 0.40
                )


        except Exception:

            ml_prediction = "error"

            ml_confidence = 0

            ml_contribution = 0


    # --------------------------------------------------------
    # FINAL RISK SCORE
    # --------------------------------------------------------

    final_score = max(
        rule_score,
        ml_contribution
    )


    # --------------------------------------------------------
    # STRONG INDICATOR ESCALATION
    # --------------------------------------------------------

    strong_indicators = [

        "urgent",
        "verify your account",
        "verify account",
        "send your otp",
        "bank account",
        "password",
        "credit card",
        "claim your prize",
        "free money"

    ]


    strong_indicator_count = 0


    for indicator in strong_indicators:

        if indicator in message_lower:

            strong_indicator_count += 1


    if (

        strong_indicator_count >= 2

        and len(detected_urls) > 0

        and highest_url_score >= 40

    ):

        final_score = max(
            final_score,
            70
        )


    # --------------------------------------------------------
    # CAP FINAL SCORE
    # --------------------------------------------------------

    final_score = min(
        final_score,
        100
    )


    # --------------------------------------------------------
    # FINAL RISK LEVEL
    # --------------------------------------------------------

    if final_score >= 70:

        risk_level = "HIGH"

        status = (
            "High-risk content detected"
        )

    elif final_score >= 30:

        risk_level = "MEDIUM"

        status = (
            "Potentially suspicious content detected"
        )

    else:

        risk_level = "LOW"

        status = (
            "No major threat detected"
        )


    return {

        "risk_score": final_score,

        "risk_level": risk_level,

        "status": status,

        "detected_urls": detected_urls,

        "matched_keywords": matched_keywords,

        "url_analysis": url_analysis,

        "ml_prediction": ml_prediction,

        "ml_confidence": ml_confidence

    }


# ============================================================
# HOME / ANALYZE
# ============================================================

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

                risk_score=result[
                    "risk_score"
                ],

                risk_level=result[
                    "risk_level"
                ],

                status=result[
                    "status"
                ],

                detected_urls=",".join(
                    result[
                        "detected_urls"
                    ]
                ),

                matched_keywords=",".join(
                    result[
                        "matched_keywords"
                    ]
                ),

                ml_prediction=result[
                    "ml_prediction"
                ],

                ml_confidence=result[
                    "ml_confidence"
                ]

            )


    return render(

        request,

        "detector/home.html",

        {
            "result": result
        }

    )


# ============================================================
# HISTORY
# ============================================================

def history(request):

    detections = Detection.objects.order_by(
        "-created_at"
    )


    total_count = Detection.objects.count()


    high_count = Detection.objects.filter(
        risk_level="HIGH"
    ).count()


    medium_count = Detection.objects.filter(
        risk_level="MEDIUM"
    ).count()


    low_count = Detection.objects.filter(
        risk_level="LOW"
    ).count()


    context = {

        "detections": detections,

        "total_count": total_count,

        "high_count": high_count,

        "medium_count": medium_count,

        "low_count": low_count

    }


    return render(

        request,

        "detector/history.html",

        context

    )


# ============================================================
# DASHBOARD
# ============================================================

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


    # --------------------------------------------------------
    # RISK PERCENTAGES
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # MACHINE LEARNING STATISTICS
    # --------------------------------------------------------

    ml_spam_count = Detection.objects.filter(
        ml_prediction="spam"
    ).count()


    ml_safe_count = Detection.objects.filter(
        ml_prediction="safe"
    ).count()


    ml_analyzed_count = (
        ml_spam_count
        + ml_safe_count
    )


    if ml_analyzed_count > 0:

        ml_spam_percentage = round(
            (
                ml_spam_count
                / ml_analyzed_count
            ) * 100
        )

        ml_safe_percentage = round(
            (
                ml_safe_count
                / ml_analyzed_count
            ) * 100
        )

    else:

        ml_spam_percentage = 0

        ml_safe_percentage = 0


    # --------------------------------------------------------
    # URL DETECTIONS
    # --------------------------------------------------------

    url_detection_count = (
        Detection.objects
        .exclude(
            detected_urls=""
        )
        .count()
    )


    # --------------------------------------------------------
    # RECENT DETECTIONS
    # --------------------------------------------------------

    recent_detections = (
        Detection.objects
        .order_by(
            "-created_at"
        )[:5]
    )


    # --------------------------------------------------------
    # DAILY DETECTION DATA
    # --------------------------------------------------------

    daily_detections = (
        Detection.objects
        .annotate(
            date=TruncDate(
                "created_at"
            )
        )
        .values(
            "date"
        )
        .annotate(
            count=Count(
                "id"
            )
        )
        .order_by(
            "date"
        )
    )


    chart_labels = [

        item["date"].strftime(
            "%d %b"
        )

        for item in daily_detections

        if item["date"] is not None

    ]


    chart_values = [

        item["count"]

        for item in daily_detections

        if item["date"] is not None

    ]


    # --------------------------------------------------------
    # CONTEXT
    # --------------------------------------------------------

    context = {

        "total": total,

        "low": low,

        "medium": medium,

        "high": high,

        "low_percentage":
            low_percentage,

        "medium_percentage":
            medium_percentage,

        "high_percentage":
            high_percentage,

        "risky_percentage":
            risky_percentage,

        "ml_spam_count":
            ml_spam_count,

        "ml_safe_count":
            ml_safe_count,

        "ml_analyzed_count":
            ml_analyzed_count,

        "ml_spam_percentage":
            ml_spam_percentage,

        "ml_safe_percentage":
            ml_safe_percentage,

        "url_detection_count":
            url_detection_count,

        "recent_detections":
            recent_detections,

        "chart_labels":
            chart_labels,

        "chart_values":
            chart_values

    }


    return render(

        request,

        "detector/dashboard.html",

        context

    )


# ============================================================
# DETECTION DETAILS
# ============================================================

def detection_detail(request, id):

    detection = Detection.objects.get(
        id=id
    )


    # --------------------------------------------------------
    # DETECTED URLS
    # --------------------------------------------------------

    detected_urls = [

        url.strip()

        for url in
        detection.detected_urls.split(",")

        if url.strip()

    ]


    # --------------------------------------------------------
    # MATCHED KEYWORDS
    # --------------------------------------------------------

    matched_keywords = [

        keyword.strip()

        for keyword in
        detection.matched_keywords.split(",")

        if keyword.strip()

    ]


    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    url_analysis = []


    for url in detected_urls:

        analysis = analyze_url(
            url
        )

        url_analysis.append(
            analysis
        )


    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render(

        request,

        "detector/detection_detail.html",

        {

            "detection":
                detection,

            "url_analysis":
                url_analysis,

            "matched_keywords":
                matched_keywords

        }

    )