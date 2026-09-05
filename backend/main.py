from urllib.parse import urlparse
from ipaddress import ip_address
import hashlib
import re
import os
import time
import json
import sqlite3
from datetime import datetime, timezone

from dotenv import load_dotenv
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")
load_dotenv(dotenv_path=ENV_FILE, override=False)


# =========================================================
# SCAN HISTORY DATABASE
# =========================================================

DB_FILE = os.path.join(BASE_DIR, "cybersentinel.db")


def get_db_connection():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_scan_history_db():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                summary TEXT NOT NULL,
                indicators TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def save_scan_history(scan_result):
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_history
            (url, domain, score, status, risk_level, summary, indicators, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_result["url"],
                scan_result["domain"],
                scan_result["score"],
                scan_result["status"],
                scan_result["risk_level"],
                scan_result["summary"],
                json.dumps(scan_result["indicators"]),
                scan_result["scanned_at"],
            ),
        )
        connection.commit()


def get_scan_history(limit=20):
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, url, domain, score, status, risk_level,
                   summary, indicators, scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    history = []
    for row in rows:
        history.append({
            "id": row["id"],
            "url": row["url"],
            "domain": row["domain"],
            "score": row["score"],
            "status": row["status"],
            "risk_level": row["risk_level"],
            "summary": row["summary"],
            "indicators": json.loads(row["indicators"]),
            "scanned_at": row["scanned_at"],
        })

    return history


def clear_scan_history():
    with get_db_connection() as connection:
        connection.execute("DELETE FROM scan_history")
        connection.commit()


init_scan_history_db()


app = FastAPI(
    title="CyberSentinel AI",
    description="AI-powered cybersecurity analysis API",
    version="1.1.0",
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

# =========================================================
# SCAN HISTORY API
# =========================================================

@app.get("/api/scan/history")
def scan_history():
    return {
        "success": True,
        "history": get_scan_history(20),
    }


@app.get("/api/scan/stats")
def scan_stats():
    with get_db_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history"
        ).fetchone()["count"]

        safe = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE status = 'safe'"
        ).fetchone()["count"]

        suspicious = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE status = 'suspicious'"
        ).fetchone()["count"]

        threat = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE status = 'threat'"
        ).fetchone()["count"]

        average_score = connection.execute(
            "SELECT COALESCE(AVG(score), 0) AS average FROM scan_history"
        ).fetchone()["average"]

    return {
        "success": True,
        "stats": {
            "total_scans": total,
            "safe_urls": safe,
            "suspicious_urls": suspicious,
            "threats_detected": threat,
            "average_risk_score": round(average_score, 1),
        },
    }


@app.delete("/api/scan/history")
def delete_scan_history():
    clear_scan_history()
    return {
        "success": True,
        "message": "Scan history cleared.",
    }


# =========================================================
# GOOGLE SAFE BROWSING REPUTATION CHECK
# =========================================================

def check_url_reputation(url: str):
    """Check a URL against Google Safe Browsing threat lists."""

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "not_configured",
            "value": "Reputation API not configured",
            "safe": True,
            "risk_points": 0,
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={api_key}"
    )

    payload = {
        "client": {
            "clientId": "cybersentinel-ai",
            "clientVersion": "1.1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=8,
        )

        if response.status_code != 200:
            return {
                "status": "unavailable",
                "value": (
                    f"Reputation check unavailable "
                    f"(HTTP {response.status_code})"
                ),
                "safe": False,
                "risk_points": 0,
            }

        data = response.json()
        matches = data.get("matches", [])

        if matches:
            threat_types = sorted({
                match.get("threatType", "UNKNOWN")
                for match in matches
            })

            readable_types = []
            threat_labels = {
                "SOCIAL_ENGINEERING": "Phishing",
                "MALWARE": "Malware",
                "UNWANTED_SOFTWARE": "Unwanted software",
                "POTENTIALLY_HARMFUL_APPLICATION": "Potentially harmful",
            }

            for threat in threat_types:
                readable_types.append(
                    threat_labels.get(threat, threat)
                )

            return {
                "status": "malicious",
                "value": (
                    "Threat detected: "
                    + ", ".join(readable_types)
                ),
                "safe": False,
                "risk_points": 70,
            }

        return {
            "status": "clean",
            "value": "No known threat found",
            "safe": True,
            "risk_points": 0,
        }

    except requests.Timeout:
        return {
            "status": "timeout",
            "value": "Reputation check timed out",
            "safe": False,
            "risk_points": 0,
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "value": "Reputation service unavailable",
            "safe": False,
            "risk_points": 0,
        }

    # =========================================================
# VIRUSTOTAL URL REPUTATION CHECK
# =========================================================

def check_virustotal(url: str):
    """Submit a URL to VirusTotal and poll until the analysis is completed."""

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "not_configured",
            "value": "VirusTotal API not configured",
            "safe": True,
            "risk_points": 0,
        }

    # VirusTotal expects a real HTTP/HTTPS URL.
    if not url or not url.lower().startswith(("http://", "https://")):
        return {
            "status": "unavailable",
            "value": "VirusTotal received an invalid URL",
            "safe": False,
            "risk_points": 0,
        }

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        # Submit URL for analysis.
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15,
        )

        if response.status_code not in (200, 201):
            try:
                error_data = response.json()
                error_message = (
                    error_data.get("error", {}).get("message")
                    or error_data.get("error", {}).get("code")
                    or response.text[:300]
                )
            except ValueError:
                error_message = response.text[:300]

            return {
                "status": "unavailable",
                "value": (
                    f"VirusTotal HTTP {response.status_code}: "
                    f"{error_message}"
                ),
                "safe": False,
                "risk_points": 0,
            }

        try:
            analysis_id = response.json().get("data", {}).get("id")
        except ValueError:
            analysis_id = None

        if not analysis_id:
            return {
                "status": "unavailable",
                "value": "VirusTotal analysis ID not received",
                "safe": False,
                "risk_points": 0,
            }

        # VirusTotal analysis is asynchronous, so poll for completion.
        analysis = None

        for _ in range(10):
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=15,
            )

            if analysis_response.status_code != 200:
                try:
                    error_data = analysis_response.json()
                    error_message = (
                        error_data.get("error", {}).get("message")
                        or error_data.get("error", {}).get("code")
                        or analysis_response.text[:300]
                    )
                except ValueError:
                    error_message = analysis_response.text[:300]

                return {
                    "status": "unavailable",
                    "value": (
                        f"VirusTotal result HTTP "
                        f"{analysis_response.status_code}: "
                        f"{error_message}"
                    ),
                    "safe": False,
                    "risk_points": 0,
                }

            try:
                analysis = analysis_response.json()
            except ValueError:
                return {
                    "status": "unavailable",
                    "value": "VirusTotal returned an invalid response",
                    "safe": False,
                    "risk_points": 0,
                }

            status = (
                analysis.get("data", {})
                .get("attributes", {})
                .get("status")
            )

            if status == "completed":
                break

            time.sleep(2)

        final_status = (
            analysis.get("data", {})
            .get("attributes", {})
            .get("status")
            if analysis else None
        )

        if final_status != "completed":
            return {
                "status": "pending",
                "value": (
                    "VirusTotal analysis is still processing. "
                    "Please scan again in a few seconds."
                ),
                "safe": True,
                "risk_points": 0,
            }

        stats = (
            analysis.get("data", {})
            .get("attributes", {})
            .get("stats", {})
        )

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        timeout = int(stats.get("timeout", 0))

        total = malicious + suspicious + harmless + undetected + timeout

        if malicious > 0:
            return {
                "status": "malicious",
                "value": (
                    f"{malicious}/{total} security engines "
                    "flagged this URL as malicious"
                ),
                "safe": False,
                "risk_points": min(70, malicious * 10),
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout,
                "total": total,
            }

        if suspicious > 0:
            return {
                "status": "suspicious",
                "value": (
                    f"{suspicious}/{total} security engines "
                    "flagged this URL as suspicious"
                ),
                "safe": False,
                "risk_points": min(35, suspicious * 7),
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout,
                "total": total,
            }

        return {
            "status": "clean",
            "value": f"No malicious detections ({total} engines checked)",
            "safe": True,
            "risk_points": 0,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total": total,
        }

    except requests.Timeout:
        return {
            "status": "timeout",
            "value": "VirusTotal check timed out",
            "safe": False,
            "risk_points": 0,
        }

    except requests.RequestException as exc:
        return {
            "status": "unavailable",
            "value": f"VirusTotal service unavailable: {str(exc)[:200]}",
            "safe": False,
            "risk_points": 0,
        }

    except Exception as exc:
        return {
            "status": "unavailable",
            "value": f"VirusTotal analysis failed: {str(exc)[:200]}",
            "safe": False,
            "risk_points": 0,
        }


@app.post("/api/scan/url")
def scan_url(request: URLScanRequest):

    raw_url = request.url.strip()

    if not raw_url:
        return {
            "success": False,
            "error": "Please enter a URL.",
        }

    # ---------------------------------------------------------
    # NORMALIZE URL
    # ---------------------------------------------------------

    if not raw_url.lower().startswith(("http://", "https://")):
        normalized_url = "https://" + raw_url
    else:
        normalized_url = raw_url

    # ---------------------------------------------------------
    # PARSE URL
    # ---------------------------------------------------------

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

    # =========================================================
    # 1. HTTPS CHECK
    # =========================================================

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

    # =========================================================
    # 2. IP ADDRESS CHECK
    # =========================================================

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

    # =========================================================
    # 3. SUSPICIOUS KEYWORDS
    # =========================================================

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
        "support",
        "unlock",
        "authenticate",
        "credential",
    ]

    hostname_matches = [
        word
        for word in suspicious_words
        if word in hostname
    ]

    path_and_query = (
        f"{parsed.path}?{parsed.query}"
    ).lower()

    url_matches = [
        word
        for word in suspicious_words
        if word in path_and_query
    ]

    matched_words = sorted(
        set(hostname_matches + url_matches)
    )

    if matched_words:
        indicators.append({
            "label": "Suspicious keywords",
            "value": ", ".join(matched_words),
            "safe": False,
        })

        risk_points += min(len(matched_words) * 7, 30)

    else:
        indicators.append({
            "label": "Suspicious keywords",
            "value": "None detected",
            "safe": True,
        })

    # =========================================================
    # 4. DOMAIN STRUCTURE
    # =========================================================

    domain_parts = hostname.split(".")

    if len(domain_parts) > 4:
        indicators.append({
            "label": "Domain structure",
            "value": "Excessive subdomains",
            "safe": False,
        })
        risk_points += 20

    elif len(domain_parts) > 3:
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

    # =========================================================
    # 5. URL LENGTH
    # =========================================================

    url_length = len(normalized_url)

    if url_length > 250:
        indicators.append({
            "label": "URL length",
            "value": f"{url_length} characters — Very long",
            "safe": False,
        })
        risk_points += 15

    elif url_length > 150:
        indicators.append({
            "label": "URL length",
            "value": f"{url_length} characters — Long",
            "safe": False,
        })
        risk_points += 10

    else:
        indicators.append({
            "label": "URL length",
            "value": f"{url_length} characters — Normal",
            "safe": True,
        })

    # =========================================================
    # 6. PORT CHECK
    # =========================================================

    suspicious_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP Proxy",
        8443: "Alternative HTTPS",
    }

    try:
        port = parsed.port
    except ValueError:
        port = None

    if port is None:
        indicators.append({
            "label": "Network port",
            "value": "Standard port",
            "safe": True,
        })

    elif port in suspicious_ports:
        indicators.append({
            "label": "Network port",
            "value": f"Port {port} ({suspicious_ports[port]})",
            "safe": False,
        })
        risk_points += 10

    else:
        indicators.append({
            "label": "Network port",
            "value": f"Custom port {port}",
            "safe": False,
        })
        risk_points += 5

    # =========================================================
    # 7. @ SYMBOL CHECK
    # =========================================================

    if "@" in normalized_url:
        indicators.append({
            "label": "URL obfuscation",
            "value": "@ symbol detected",
            "safe": False,
        })
        risk_points += 20
    else:
        indicators.append({
            "label": "URL obfuscation",
            "value": "No @ symbol detected",
            "safe": True,
        })

    # =========================================================
    # 8. ENCODED CHARACTER CHECK
    # =========================================================

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        normalized_url,
    )

    if len(encoded_matches) >= 5:
        indicators.append({
            "label": "Encoded characters",
            "value": f"{len(encoded_matches)} encoded sequences",
            "safe": False,
        })
        risk_points += 10

    elif encoded_matches:
        indicators.append({
            "label": "Encoded characters",
            "value": f"{len(encoded_matches)} encoded sequence(s)",
            "safe": True,
        })

    else:
        indicators.append({
            "label": "Encoded characters",
            "value": "None detected",
            "safe": True,
        })

    # =========================================================
    # 9. SUSPICIOUS TLD
    # =========================================================

    suspicious_tlds = {
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".click",
        ".top",
        ".zip",
        ".mov",
        ".work",
        ".country",
        ".support",
        ".download",
    }

    matched_tld = None

    for tld in suspicious_tlds:
        if hostname.endswith(tld):
            matched_tld = tld
            break

    if matched_tld:
        indicators.append({
            "label": "Domain extension",
            "value": f"Potentially risky TLD {matched_tld}",
            "safe": False,
        })
        risk_points += 15

    else:
        indicators.append({
            "label": "Domain extension",
            "value": "No high-risk TLD detected",
            "safe": True,
        })

    # =========================================================
    # 10. HYPHEN / DOMAIN OBFUSCATION
    # =========================================================

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:
        indicators.append({
            "label": "Domain naming",
            "value": f"{hyphen_count} hyphens detected",
            "safe": False,
        })
        risk_points += 10

    else:
        indicators.append({
            "label": "Domain naming",
            "value": "Normal",
            "safe": True,
        })

    # =========================================================
    # 11. SUSPICIOUS PATH
    # =========================================================

    suspicious_path_patterns = [
        r"/login",
        r"/signin",
        r"/verify",
        r"/account",
        r"/password",
        r"/payment",
        r"/wallet",
        r"/credential",
        r"/auth",
        r"/secure",
    ]

    path_matches = [
        pattern
        for pattern in suspicious_path_patterns
        if re.search(pattern, parsed.path.lower())
    ]

    if path_matches:
        indicators.append({
            "label": "URL path",
            "value": "Sensitive-looking path detected",
            "safe": False,
        })
        risk_points += 10

    else:
        indicators.append({
            "label": "URL path",
            "value": "No obvious sensitive path",
            "safe": True,
        })

    # =========================================================
    # 12. QUERY PARAMETERS
    # =========================================================

    query_length = len(parsed.query)

    if query_length > 150:
        indicators.append({
            "label": "Query parameters",
            "value": "Unusually large query string",
            "safe": False,
        })
        risk_points += 10

    else:
        indicators.append({
            "label": "Query parameters",
            "value": "Normal",
            "safe": True,
        })

    # =========================================================
    # 13. DOUBLE SLASH / OBFUSCATION
    # =========================================================

    suspicious_double_slash = (
        "//" in parsed.path
    )

    if suspicious_double_slash:
        indicators.append({
            "label": "Path structure",
            "value": "Unusual double slash detected",
            "safe": False,
        })
        risk_points += 5

    else:
        indicators.append({
            "label": "Path structure",
            "value": "Normal",
            "safe": True,
        })

    # =========================================================
    # 14. PHISHING / DOMAIN REPUTATION
    # =========================================================

    reputation = check_url_reputation(normalized_url)

    if reputation["status"] == "malicious":
        indicators.append({
            "label": "Domain reputation",
            "value": reputation["value"],
            "safe": False,
        })
        risk_points += reputation["risk_points"]

    elif reputation["status"] == "clean":
        indicators.append({
            "label": "Domain reputation",
            "value": reputation["value"],
            "safe": True,
        })

    elif reputation["status"] == "not_configured":
        indicators.append({
            "label": "Domain reputation",
            "value": "Not configured",
            "safe": True,
        })

    else:
        indicators.append({
            "label": "Domain reputation",
            "value": reputation["value"],
            "safe": False,
        })

        # =========================================================
    # 15. VIRUSTOTAL REPUTATION
    # =========================================================

    virustotal = check_virustotal(normalized_url)

    if virustotal["status"] == "malicious":
        indicators.append({
            "label": "VirusTotal",
            "value": virustotal["value"],
            "safe": False,
        })
        risk_points += virustotal["risk_points"]

    elif virustotal["status"] == "suspicious":
        indicators.append({
            "label": "VirusTotal",
            "value": virustotal["value"],
            "safe": False,
        })
        risk_points += virustotal["risk_points"]

    elif virustotal["status"] == "clean":
        indicators.append({
            "label": "VirusTotal",
            "value": virustotal["value"],
            "safe": True,
        })

    elif virustotal["status"] == "not_configured":
        indicators.append({
            "label": "VirusTotal",
            "value": "Not configured",
            "safe": True,
        })

    elif virustotal["status"] == "pending":
        indicators.append({
            "label": "VirusTotal",
            "value": virustotal["value"],
            "safe": True,
        })

    else:
        indicators.append({
            "label": "VirusTotal",
            "value": virustotal["value"],
            "safe": False,
        })

    # =========================================================
    # FINAL SCORE
    # =========================================================

    risk_points = min(risk_points, 100)
    score = 100 - risk_points

    # =========================================================
    # CLASSIFICATION
    # =========================================================

    if risk_points >= 60:
        status = "threat"
        risk_level = "High"
        summary = (
            "Multiple high-risk indicators were detected. "
            "This URL should be treated as potentially malicious "
            "and should not be trusted without further verification."
        )

    elif risk_points >= 25:
        status = "suspicious"
        risk_level = "Medium"
        summary = (
            "Several suspicious patterns were detected. "
            "Verify the domain and destination before interacting "
            "with this URL."
        )

    else:
        status = "safe"
        risk_level = "Low"
        summary = (
            "No obvious high-risk patterns were detected "
            "during this initial static URL analysis."
        )

    # =========================================================
    # RESPONSE
    # =========================================================

    scan_result = {
        "success": True,
        "url": normalized_url,
        "domain": hostname,
        "score": score,
        "status": status,
        "risk_level": risk_level,
        "summary": summary,
        "indicators": indicators,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    save_scan_history(scan_result)

    return scan_result


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
    # =========================================================

    score = 0

    # =========================================================
    # LENGTH SCORE
    # =========================================================

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

    # =========================================================
    # CHARACTER DIVERSITY
    # =========================================================

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

    # =========================================================
    # REPETITION CHECK
    # =========================================================

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

    # =========================================================
    # COMMON PATTERN CHECK
    # =========================================================

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

    # =========================================================
    # COMMON PASSWORD CHECK
    # =========================================================

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