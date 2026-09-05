import io
from fastapi.responses import StreamingResponse
from urllib.parse import urlparse
from ipaddress import ip_address
import hashlib
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
from datetime import datetime, timezone

from dotenv import load_dotenv
import requests
from fastapi import FastAPI, Depends, HTTPException, Header, status as http_status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext

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


# =========================================================
# AUTHENTICATION
# =========================================================

def init_users_db():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

JWT_ALGORITHM = "HS256"
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "cybersentinel-development-secret-change-me",
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "iat": int(time.time()),
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


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
                scanned_at TEXT NOT NULL,
                user_id INTEGER
            )
            """
        )

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scan_history)"
            ).fetchall()
        }

        if "user_id" not in columns:
            connection.execute(
                "ALTER TABLE scan_history ADD COLUMN user_id INTEGER"
            )

        connection.commit()


def save_scan_history(scan_result, user_id: int):
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_history
            (url, domain, score, status, risk_level, summary, indicators, scanned_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                user_id,
            ),
        )
        connection.commit()


def get_scan_history(user_id: int, limit=20):
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, url, domain, score, status, risk_level,
                   summary, indicators, scanned_at
            FROM scan_history
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
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


def clear_scan_history(user_id: int):
    with get_db_connection() as connection:
        connection.execute(
            "DELETE FROM scan_history WHERE user_id = ?",
            (user_id,),
        )
        connection.commit()


init_users_db()
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


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


# =========================================================
# AUTH HELPERS
# =========================================================

def get_current_user_id_from_token(
    authorization: str | None = None,
) -> int:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
        subject = payload.get("sub")

        if not subject:
            raise ValueError("Missing user id")

        user_id = int(subject)
    except (JWTError, ValueError, TypeError):
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        )

    with get_db_connection() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if not user:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
        )

    return user_id


# =========================================================
# AUTHENTICATION API
# =========================================================

@app.post("/api/auth/register")
def register(request: RegisterRequest):
    name = request.name.strip()
    email = request.email.strip().lower()
    password = request.password

    if len(name) < 2:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Name must be at least 2 characters.",
        )

    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Please enter a valid email address.",
        )

    if len(password) < 8:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters.",
        )

    with get_db_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="An account with this email already exists.",
            )

        cursor = connection.execute(
            """
            INSERT INTO users (name, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                email,
                hash_password(password),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
        user_id = cursor.lastrowid

    token = create_access_token(user_id)

    return {
        "success": True,
        "message": "Account created successfully.",
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
        },
    }


@app.post("/api/auth/login")
def login(request: LoginRequest):
    email = request.email.strip().lower()

    with get_db_connection() as connection:
        user = connection.execute(
            """
            SELECT id, name, email, password_hash, created_at
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    token = create_access_token(user["id"])

    return {
        "success": True,
        "message": "Login successful.",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "created_at": user["created_at"],
        },
    }


@app.get("/api/auth/me")
def me(authorization: str | None = Header(default=None)):
    user_id = get_current_user_id_from_token(authorization)

    with get_db_connection() as connection:
        user = connection.execute(
            """
            SELECT id, name, email, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    return {
        "success": True,
        "user": dict(user),
    }


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
def scan_history(authorization: str | None = Header(default=None)):
    user_id = get_current_user_id_from_token(authorization)
    return {
        "success": True,
        "history": get_scan_history(user_id, 20),
    }


@app.get("/api/scan/stats")
def scan_stats(authorization: str | None = Header(default=None)):
    user_id = get_current_user_id_from_token(authorization)

    with get_db_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE user_id = ?",
            (user_id,),
        ).fetchone()["count"]

        safe = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE user_id = ? AND status = 'safe'",
            (user_id,),
        ).fetchone()["count"]

        suspicious = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE user_id = ? AND status = 'suspicious'",
            (user_id,),
        ).fetchone()["count"]

        threat = connection.execute(
            "SELECT COUNT(*) AS count FROM scan_history WHERE user_id = ? AND status = 'threat'",
            (user_id,),
        ).fetchone()["count"]

        average_score = connection.execute(
            "SELECT COALESCE(AVG(score), 0) AS average FROM scan_history WHERE user_id = ?",
            (user_id,),
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
def delete_scan_history(authorization: str | None = Header(default=None)):
    user_id = get_current_user_id_from_token(authorization)
    clear_scan_history(user_id)
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
            timeout=5,
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
            timeout=8,
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

        for _ in range(4):
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=8,
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

            time.sleep(1)

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
def scan_url(
    request: URLScanRequest,
    authorization: str | None = Header(default=None),
):
    user_id = get_current_user_id_from_token(authorization)

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
    # 14-15. EXTERNAL THREAT INTELLIGENCE (PARALLEL)
    # =========================================================
    # Google Safe Browsing and VirusTotal are independent network
    # checks, so run them together to reduce total scan latency.
    with ThreadPoolExecutor(max_workers=2) as executor:
        reputation_future = executor.submit(check_url_reputation, normalized_url)
        virustotal_future = executor.submit(check_virustotal, normalized_url)

        reputation = reputation_future.result()
        virustotal = virustotal_future.result()

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

    save_scan_history(scan_result, user_id)

    return scan_result


# =========================================================
# PASSWORD ANALYZER
# =========================================================

@app.post("/api/analyze/password")
def analyze_password(
    request: PasswordAnalyzeRequest,
    authorization: str | None = Header(default=None),
):
    get_current_user_id_from_token(authorization)

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

# =========================================================
# PDF SECURITY REPORT
# =========================================================

class SecurityReportRequest(BaseModel):
    url: str
    score: int
    status: str
    risk_level: str
    summary: str
    indicators: list[dict]
    scanned_at: str | None = None


@app.post("/api/report/pdf")
def generate_security_report(
    request: SecurityReportRequest,
    authorization: str | None = Header(default=None),
):
    get_current_user_id_from_token(authorization)
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    from reportlab.lib import colors

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="CyberSentinel AI Security Report",
        author="CyberSentinel AI",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], alignment=TA_CENTER,
        fontSize=22, leading=27, spaceAfter=5, textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], alignment=TA_CENTER,
        fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=18
    )
    heading_style = ParagraphStyle(
        "ReportHeading", parent=styles["Heading2"], fontSize=13, leading=16,
        textColor=colors.HexColor("#0f172a"), spaceBefore=12, spaceAfter=8
    )
    body_style = ParagraphStyle(
        "ReportBody", parent=styles["BodyText"], fontSize=9.5, leading=14,
        textColor=colors.HexColor("#334155")
    )
    small_style = ParagraphStyle(
        "ReportSmall", parent=styles["BodyText"], fontSize=8, leading=11,
        textColor=colors.HexColor("#64748b")
    )

    status = request.status.lower()
    if status == "threat":
        status_color = colors.HexColor("#dc2626")
        status_label = "THREAT DETECTED"
    elif status == "suspicious":
        status_color = colors.HexColor("#ca8a04")
        status_label = "SUSPICIOUS"
    else:
        status_color = colors.HexColor("#059669")
        status_label = "SAFE"

    scanned_at = request.scanned_at or datetime.now().astimezone().isoformat()
    safe_url = request.url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    story = [
        Paragraph("CyberSentinel AI", title_style),
        Paragraph("URL Security Assessment Report", subtitle_style),
    ]

    overview = [
        [Paragraph("Scanned URL", body_style), Paragraph(safe_url, body_style)],
        [Paragraph("Scan Time", body_style), Paragraph(scanned_at, body_style)],
        [Paragraph("Risk Score", body_style), Paragraph(f"<b>{request.score}/100</b>", body_style)],
        [Paragraph("Risk Level", body_style), Paragraph(request.risk_level, body_style)],
        [Paragraph("Final Status", body_style), Paragraph(f'<font color="{status_color.hexval()}"><b>{status_label}</b></font>', body_style)],
    ]
    table = Table(overview, colWidths=[38 * mm, 132 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story += [table, Spacer(1, 8)]

    story.append(Paragraph("Security Summary", heading_style))
    story.append(Paragraph(request.summary or "No summary was provided.", body_style))

    story.append(Paragraph("Security Indicators", heading_style))
    indicator_rows = [[
        Paragraph("Indicator", body_style),
        Paragraph("Result", body_style),
        Paragraph("Status", body_style),
    ]]
    for item in request.indicators:
        label = str(item.get("label", "Unknown"))
        value = str(item.get("value", ""))
        is_safe = bool(item.get("safe", False))
        status_text = "PASS" if is_safe else "REVIEW"
        status_hex = "#059669" if is_safe else "#ca8a04"
        indicator_rows.append([
            Paragraph(label, body_style),
            Paragraph(value, body_style),
            Paragraph(f'<font color="{status_hex}"><b>{status_text}</b></font>', body_style),
        ])

    if len(indicator_rows) == 1:
        indicator_rows.append([Paragraph("No indicators available.", body_style), "", ""])

    indicator_table = Table(indicator_rows, colWidths=[65 * mm, 80 * mm, 25 * mm], repeatRows=1)
    indicator_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(indicator_table)

    story.append(Paragraph("Assessment Notice", heading_style))
    story.append(Paragraph(
        "This report is an automated security assessment generated by CyberSentinel AI. "
        "A low-risk result does not guarantee that a website is completely safe. "
        "Use this report as an additional security signal, not as a sole basis for trust decisions.",
        small_style,
    ))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Generated by CyberSentinel AI", small_style))

    doc.build(story)
    buffer.seek(0)

    filename = "CyberSentinel_Security_Report.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )



