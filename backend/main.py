from urllib.parse import urlparse
from ipaddress import ip_address
import hashlib
import re

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI(
    title="CyberSentinel AI",
    description="AI-powered cybersecurity analysis API",
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# REQUEST MODELS
# =========================================================

class URLScanRequest(BaseModel):
    url: str


class PasswordAnalyzeRequest(BaseModel):
    password: str


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "name": "CyberSentinel AI",
        "status": "online",
        "message": "Cybersecurity API is running",
    }


# =========================================================
# HEALTH
# =========================================================

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "CyberSentinel AI API",
    }


# =========================================================
# URL SCANNER
# =========================================================

@app.post("/api/scan/url")
def scan_url(request: URLScanRequest):

    raw_url = request.url.strip()

    if not raw_url:
        return {
            "success": False,
            "error": "Please enter a URL.",
        }

    # Add HTTPS if user enters example.com
    if not raw_url.lower().startswith(("http://", "https://")):
        normalized_url = "https://" + raw_url
    else:
        normalized_url = raw_url

    # Parse URL
    try:
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname
    except Exception:
        return {
            "success": False,
            "error": "Invalid URL.",
        }

    if not hostname:
        return {
            "success": False,
            "error": "Invalid URL or hostname.",
        }

    hostname = hostname.lower()

    indicators = []
    risk_points = 0

    # ---------------------------------------------------------
    # HTTPS CHECK
    # ---------------------------------------------------------

    if parsed.scheme.lower() == "https":
        indicators.append({
            "label": "HTTPS",
            "value": "Enabled",
            "safe": True,
        })
    else:
        indicators.append({
            "label": "HTTPS",
            "value": "Not enabled",
            "safe": False,
        })
        risk_points += 25

    # ---------------------------------------------------------
    # IP ADDRESS CHECK
    # ---------------------------------------------------------

    try:
        ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        indicators.append({
            "label": "Host type",
            "value": "IP address detected",
            "safe": False,
        })
        risk_points += 25
    else:
        indicators.append({
            "label": "Host type",
            "value": "Domain name",
            "safe": True,
        })

    # ---------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "payment",
        "signin",
        "confirm",
        "wallet",
        "password",
        "bank",
    ]

    matched_words = [
        word
        for word in suspicious_words
        if word in hostname
    ]

    if matched_words:
        indicators.append({
            "label": "Suspicious keywords",
            "value": ", ".join(matched_words),
            "safe": False,
        })

        risk_points += min(
            len(matched_words) * 10,
            30,
        )
    else:
        indicators.append({
            "label": "Suspicious keywords",
            "value": "None detected",
            "safe": True,
        })

    # ---------------------------------------------------------
    # DOMAIN STRUCTURE
    # ---------------------------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) > 3:
        indicators.append({
            "label": "Domain structure",
            "value": "Multiple subdomains",
            "safe": False,
        })
        risk_points += 15
    else:
        indicators.append({
            "label": "Domain structure",
            "value": "Normal",
            "safe": True,
        })

    # ---------------------------------------------------------
    # URL LENGTH
    # ---------------------------------------------------------

    if len(normalized_url) > 150:
        indicators.append({
            "label": "URL length",
            "value": "Unusually long",
            "safe": False,
        })
        risk_points += 10
    else:
        indicators.append({
            "label": "URL length",
            "value": "Normal",
            "safe": True,
        })

    # ---------------------------------------------------------
    # URL SCORE
    # ---------------------------------------------------------

    risk_points = min(risk_points, 100)
    score = 100 - risk_points

    if risk_points >= 60:
        status = "threat"
        risk_level = "High"
        summary = (
            "Multiple suspicious indicators were detected. "
            "This URL should be treated with caution."
        )

    elif risk_points >= 25:
        status = "suspicious"
        risk_level = "Medium"
        summary = (
            "Some suspicious patterns were detected. "
            "Additional verification is recommended."
        )

    else:
        status = "safe"
        risk_level = "Low"
        summary = (
            "No obvious high-risk patterns were detected "
            "in this initial analysis."
        )

    return {
        "success": True,
        "url": normalized_url,
        "domain": hostname,
        "score": score,
        "status": status,
        "risk_level": risk_level,
        "summary": summary,
        "indicators": indicators,
    }


# =========================================================
# PASSWORD ANALYZER
# =========================================================

@app.post("/api/analyze/password")
def analyze_password(request: PasswordAnalyzeRequest):

    password = request.password

    if not password:
        return {
            "success": False,
            "error": "Password is required.",
        }

    indicators = []
    recommendations = []

    # =========================================================
    # BASIC VARIABLES
    # =========================================================

    length = len(password)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    diversity = sum([
        has_lower,
        has_upper,
        has_digit,
        has_special,
    ])

    lowered = password.lower()

    # =========================================================
    # SCORE SYSTEM
    #
    # Start from 0 and award points for good security
    # characteristics instead of subtracting large penalties.
    # This allows genuinely strong passwords to reach 90-100.
    # =========================================================

    score = 0

    # ---------------------------------------------------------
    # LENGTH SCORE
    # ---------------------------------------------------------

    if length >= 20:
        score += 35

        indicators.append({
            "label": "Password length",
            "value": f"{length} characters — Excellent",
            "safe": True,
        })

    elif length >= 16:
        score += 32

        indicators.append({
            "label": "Password length",
            "value": f"{length} characters — Excellent",
            "safe": True,
        })

    elif length >= 14:
        score += 28

        indicators.append({
            "label": "Password length",
            "value": f"{length} characters — Strong",
            "safe": True,
        })

    elif length >= 12:
        score += 24

        indicators.append({
            "label": "Password length",
            "value": f"{length} characters — Good",
            "safe": True,
        })

    elif length >= 8:
        score += 15

        indicators.append({
            "label": "Password length",
            "value": f"{length} characters — Short",
            "safe": False,
        })

        recommendations.append(
            "Use at least 12–16 characters for better protection."
        )

    else:
        score += 5

        indicators.append({
            "label": "Password length",
            "value": f"{length} characters — Too short",
            "safe": False,
        })

        recommendations.append(
            "Use a password of at least 12 characters."
        )

    # ---------------------------------------------------------
    # CHARACTER DIVERSITY SCORE
    # ---------------------------------------------------------

    diversity_points = {
        4: 25,
        3: 20,
        2: 12,
        1: 6,
        0: 0,
    }

    score += diversity_points[diversity]

    if diversity == 4:
        indicators.append({
            "label": "Character diversity",
            "value": "Uppercase, lowercase, numbers & symbols",
            "safe": True,
        })

    elif diversity == 3:
        indicators.append({
            "label": "Character diversity",
            "value": "Good variety",
            "safe": True,
        })

        recommendations.append(
            "Add the missing character type for maximum variety."
        )

    else:
        indicators.append({
            "label": "Character diversity",
            "value": "Limited variety",
            "safe": False,
        })

        recommendations.append(
            "Mix uppercase, lowercase, numbers and symbols."
        )

    # ---------------------------------------------------------
    # REPETITION CHECK
    # ---------------------------------------------------------

    if re.search(r"(.)\1\1", password):

        score -= 10

        indicators.append({
            "label": "Repeated characters",
            "value": "Repeated pattern detected",
            "safe": False,
        })

        recommendations.append(
            "Avoid repeated characters such as aaa, 111 or !!!."
        )

    else:

        score += 5

        indicators.append({
            "label": "Repeated characters",
            "value": "No obvious repetition",
            "safe": True,
        })

    # ---------------------------------------------------------
    # COMMON PATTERN CHECK
    # ---------------------------------------------------------

    common_patterns = [
        "123456",
        "234567",
        "345678",
        "456789",
        "abcdef",
        "qwerty",
        "password",
        "admin",
        "letmein",
        "welcome",
        "iloveyou",
    ]

    found_patterns = [
        pattern
        for pattern in common_patterns
        if pattern in lowered
    ]

    if found_patterns:

        score -= 25

        indicators.append({
            "label": "Common patterns",
            "value": ", ".join(found_patterns),
            "safe": False,
        })

        recommendations.append(
            "Avoid common words, keyboard patterns and sequences."
        )

    else:

        score += 10

        indicators.append({
            "label": "Common patterns",
            "value": "No obvious common pattern",
            "safe": True,
        })

    # ---------------------------------------------------------
    # COMMON PASSWORD CHECK
    # ---------------------------------------------------------

    common_passwords = {
        "password",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "admin",
        "admin123",
        "welcome",
        "welcome123",
        "letmein",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "sunshine",
    }

    if lowered in common_passwords:

        score -= 35

        indicators.append({
            "label": "Common password",
            "value": "Known weak password",
            "safe": False,
        })

        recommendations.append(
            "Do not use commonly known passwords."
        )

    else:

        score += 5

        indicators.append({
            "label": "Common password",
            "value": "Not in basic weak-password list",
            "safe": True,
        })

    # =========================================================
    # HAVE I BEEN PWNED — K-ANONYMITY
    #
    # Only the first 5 characters of the SHA-1 hash are sent
    # to the HIBP range endpoint.
    # =========================================================

    leaked_count = 0
    breach_status = "unknown"

    try:

        sha1_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={
                "User-Agent": "CyberSentinel-AI/1.0",
                "Add-Padding": "true",
            },
            timeout=10,
        )

        if response.status_code == 200:

            breach_status = "checked"

            for line in response.text.splitlines():

                parts = line.strip().split(":")

                if len(parts) != 2:
                    continue

                returned_suffix = parts[0].strip().upper()

                if returned_suffix != suffix:
                    continue

                try:
                    leaked_count = int(
                        parts[1].strip()
                    )
                except ValueError:
                    leaked_count = 0

                break

            # -------------------------------------------------
            # PASSWORD FOUND
            # -------------------------------------------------

            if leaked_count > 0:

                score = 0

                indicators.append({
                    "label": "Breach exposure",
                    "value": (
                        f"Found {leaked_count:,} times "
                        "in known breach data"
                    ),
                    "safe": False,
                })

                recommendations.append(
                    "This password has appeared in known breach "
                    "data. Do not use it for any account."
                )

            # -------------------------------------------------
            # PASSWORD NOT FOUND
            # -------------------------------------------------

            else:

                score += 15

                indicators.append({
                    "label": "Breach exposure",
                    "value": (
                        "Not found in known breach data"
                    ),
                    "safe": True,
                })

        else:

            breach_status = "unavailable"

            indicators.append({
                "label": "Breach exposure",
                "value": (
                    f"Check unavailable "
                    f"(HTTP {response.status_code})"
                ),
                "safe": False,
            })

            recommendations.append(
                "Breach verification was unavailable. "
                "Treat this result as incomplete."
            )

    except requests.Timeout:

        breach_status = "timeout"

        indicators.append({
            "label": "Breach exposure",
            "value": "Breach check timed out",
            "safe": False,
        })

        recommendations.append(
            "Breach verification timed out. "
            "Treat this result as incomplete."
        )

    except requests.RequestException:

        breach_status = "unavailable"

        indicators.append({
            "label": "Breach exposure",
            "value": "Network check unavailable",
            "safe": False,
        })

        recommendations.append(
            "Breach verification was unavailable. "
            "Treat this result as incomplete."
        )

    # =========================================================
    # FINAL SCORE NORMALIZATION
    # =========================================================

    score = max(
        0,
        min(score, 100),
    )

    # =========================================================
    # CLASSIFICATION
    # =========================================================

    if leaked_count > 0:

        status = "weak"
        strength = "Compromised"

    elif score >= 90:

        status = "strong"
        strength = "Very Strong"

    elif score >= 75:

        status = "strong"
        strength = "Strong"

    elif score >= 50:

        status = "moderate"
        strength = "Moderate"

    else:

        status = "weak"
        strength = "Weak"

    # =========================================================
    # FINAL RECOMMENDATION
    # =========================================================

    if not recommendations:

        recommendations.append(
            "This password has a strong structure. "
            "Use a unique password for every account."
        )

    # =========================================================
    # RESPONSE
    # =========================================================

    return {
        "success": True,
        "score": score,
        "strength": strength,
        "status": status,
        "indicators": indicators,
        "recommendations": recommendations,
        "breach_count": leaked_count,
        "breach_status": breach_status,
    }