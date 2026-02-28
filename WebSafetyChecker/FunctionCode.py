import argparse
import csv
import ipaddress
import re
import socket
import ssl
import time
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
import os
import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import init
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None

try:
    import whois  # type: ignore
except Exception:  # pragma: no cover
    whois = None

try:
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover
    Image = None

init(autoreset=True)
console = Console()

APP_NAME = "Website Safety Checker"
APP_VERSION = "3.1.0"
APP_RELEASE = "2026-02-26"
APP_TAGLINE = "Rich + Markdown heuristic web security scanner"
VERDICT_CLASSES = ["Safe", "Caution", "High Risk"]


def cli_version_text() -> str:
    return (
        f"{APP_NAME} v{APP_VERSION} ({APP_RELEASE}) | "
        f"{APP_TAGLINE} | profiles=balanced,strict,phishing-focused"
    )

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "permissions-policy-report-only",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

SENSITIVE_PATHS = [
    "/robots.txt",
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.aws/credentials",
    "/id_rsa",
    "/.DS_Store",
    "/.svn/entries",
    "/.env",
    "/backup.zip",
    "/config.php.bak",
    "/debug.log",
]

SENSITIVE_BACKUP_BASES = [
    "config.php",
    "config.yaml",
    "config.yml",
    ".env",
    "database.sql",
    "dump.sql",
    "backup",
    "site-backup",
]

SENSITIVE_BACKUP_SUFFIXES = [
    ".bak",
    ".old",
    ".backup",
    ".zip",
    ".tar",
    ".tar.gz",
    ".gz",
]

SUSPICIOUS_URL_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "bank",
    "wallet",
]

REDIRECT_PARAM_NAMES = {
    "redirect",
    "redirect_url",
    "url",
    "next",
    "return",
    "return_to",
    "goto",
    "continue",
    "dest",
    "destination",
}

DOM_SOURCE_PATTERN = re.compile(
    r"location\.(href|search|hash|pathname)|document\.url|document\.location|window\.name",
    re.IGNORECASE,
)
DOM_SINK_PATTERN = re.compile(
    r"innerhtml|outerhtml|document\.write\(|eval\(|settimeout\(|setinterval\(|new\s+function\(",
    re.IGNORECASE,
)
CSRF_FIELD_HINTS = {"csrf", "token", "auth", "nonce", "verification"}

SAFE_CDN_TOKENS = [
    "googleapis.com",
    "gstatic.com",
    "cloudflare.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "bootstrapcdn.com",
]

REMEDIATION_GUIDANCE = {
    "High": "Prioritize immediate remediation and verify exploitability in a controlled environment.",
    "Medium": "Plan remediation in the next hardening cycle and monitor for abuse indicators.",
    "Low": "Track and improve as part of baseline security hygiene.",
}

WEIGHT_PROFILES: Dict[str, Dict[str, float]] = {
    "balanced": {
        "security": 0.23,
        "security_extras": 0.14,
        "phishing": 0.19,
        "application": 0.16,
        "active_probe": 0.10,
        "exposure": 0.10,
        "domain": 0.04,
        "redirect": 0.01,
        "reputation": 0.03,
    },
    "strict": {
        "security": 0.30,
        "security_extras": 0.18,
        "phishing": 0.12,
        "application": 0.14,
        "active_probe": 0.08,
        "exposure": 0.10,
        "domain": 0.04,
        "redirect": 0.02,
        "reputation": 0.02,
    },
    "phishing-focused": {
        "security": 0.16,
        "security_extras": 0.10,
        "phishing": 0.30,
        "application": 0.12,
        "active_probe": 0.07,
        "exposure": 0.07,
        "domain": 0.09,
        "redirect": 0.05,
        "reputation": 0.04,
    },
}

WEIGHT_PROFILE_LABELS = {
    "balanced": "Balanced",
    "strict": "Strict",
    "phishing-focused": "Phishing-Focused",
}

WEIGHT_PROFILE_METADATA: Dict[str, Dict[str, str]] = {
    "balanced": {
        "focus": "Balanced coverage across baseline web risks",
        "best_for": "Routine security posture checks",
        "description": "Optimized for broad, day-to-day risk visibility.",
    },
    "strict": {
        "focus": "Security headers and protocol hygiene",
        "best_for": "Hardening validation and compliance-style reviews",
        "description": "Penalizes missing hardening controls more aggressively.",
    },
    "phishing-focused": {
        "focus": "Social-engineering and domain deception signals",
        "best_for": "Brand abuse and phishing triage",
        "description": "Increases weight on phishing, domain, and redirect factors.",
    },
}

HOMOGLYPH_MAP = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}

LOCAL_PHISH_BLOCKLIST = {
    "secure-paypaI-login.com",
    "microsoft-login-security-check.com",
    "appleid-account-verify.com",
    "bank-auth-update.net",
}

POPULAR_BRAND_TOKENS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "github",
    "netflix",
    "adobe",
    "dropbox",
    "telegram",
    "openai",
    "binance",
    "coinbase",
    "chase",
    "wellsfargo",
    "bankofamerica",
]

BRAND_CANONICAL_DOMAINS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "netflix": "netflix.com",
    "adobe": "adobe.com",
    "dropbox": "dropbox.com",
    "telegram": "telegram.org",
    "openai": "openai.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
}

SCREENSHOT_API_TEMPLATE = "https://image.thum.io/get/width/1200/noanimate/{url}"


def normalize_target_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        return ""
    if not urlparse(candidate).scheme:
        candidate = f"https://{candidate}"
    return candidate


def is_url_structurally_valid(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc)


def fetch_target(url: str, timeout: int = 12, verify_ssl: bool = True) -> Tuple[requests.Response | None, str | None]:
    if not is_url_structurally_valid(url):
        return None, "Fake URL: invalid URL format."

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify_ssl)
        return response, None
    except requests.exceptions.SSLError as error:
        return None, f"SSL error: {error}"
    except requests.exceptions.ConnectionError as error:
        msg = str(error).lower()
        if (
            "failed to resolve" in msg
            or "name resolution" in msg
            or "getaddrinfo failed" in msg
            or "name or service not known" in msg
            or "nodename nor servname provided" in msg
        ):
            return None, "Fake URL: domain not resolvable (DNS lookup failed)."
        return None, f"Connection failed: {error}"
    except requests.exceptions.Timeout:
        return None, "Request timed out while connecting to target."
    except requests.exceptions.RequestException as error:
        return None, f"Request failed: {error}"


class RequestManager:
    def __init__(
        self,
        min_delay: float = 0.3,
        session: requests.Session | None = None,
        retries: int = 2,
        backoff: float = 0.4,
        timeout_budget: float = 60.0,
        max_workers: int = 6,
    ):
        self.session = session or requests.Session()
        self.cache: Dict[str, requests.Response] = {}
        self.last_request_at = 0.0
        self.min_delay = min_delay
        self.retries = retries
        self.backoff = backoff
        self.timeout_budget = timeout_budget
        self.started_at = time.time()
        self.max_workers = max_workers

    def _budget_exhausted(self) -> bool:
        return (time.time() - self.started_at) > self.timeout_budget

    def request(
        self,
        method: str,
        url: str,
        timeout: int = 8,
        allow_redirects: bool = True,
        use_cache: bool = True,
        headers: Dict[str, str] | None = None,
    ) -> requests.Response | None:
        if self._budget_exhausted():
            return None
        cache_key = f"{method.upper()}::{url}"
        if use_cache and cache_key in self.cache:
            return self.cache[cache_key]
        if use_cache and method.upper() == "GET" and url in self.cache:
            return self.cache[url]
        elapsed = time.time() - self.last_request_at
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        resp: requests.Response | None = None
        for attempt in range(self.retries + 1):
            try:
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    headers=headers,
                )
                break
            except requests.RequestException:
                if attempt >= self.retries:
                    return None
                time.sleep(self.backoff * (attempt + 1))
        if resp is None:
            return None
        if use_cache:
            self.cache[cache_key] = resp
            if method.upper() == "GET":
                self.cache[url] = resp
        self.last_request_at = time.time()
        return resp

    def get(self, url: str, timeout: int = 8, allow_redirects: bool = True) -> requests.Response | None:
        return self.request("GET", url, timeout=timeout, allow_redirects=allow_redirects, use_cache=True)

    def get_many(self, urls: List[str], timeout: int = 8) -> Dict[str, requests.Response | None]:
        results: Dict[str, requests.Response | None] = {}
        if not urls:
            return results

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(self.get, url, timeout, True): url for url in urls}
            for future in as_completed(future_map):
                url = future_map[future]
                try:
                    results[url] = future.result()
                except Exception:
                    results[url] = None
        return results


def get_set_cookie_headers(response: requests.Response) -> List[str]:
    if response.raw and hasattr(response.raw, "headers"):
        raw_headers = response.raw.headers
        if hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie")
            if values:
                return list(values)
    header_value = response.headers.get("Set-Cookie", "")
    return [header_value] if header_value else []


def _hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    host = hostname.strip().lower()
    candidate = pattern.strip().lower()
    if not host or not candidate:
        return False
    if candidate == host:
        return True
    if candidate.startswith("*."):
        suffix = candidate[1:]
        return host.endswith(suffix) and host.count(".") >= candidate.count(".")
    return False


def _hostname_matches_certificate(hostname: str, san_dns: List[str], common_names: List[str]) -> bool:
    return any(_hostname_matches_pattern(hostname, pattern) for pattern in san_dns) or any(
        _hostname_matches_pattern(hostname, pattern) for pattern in common_names
    )


def _matching_certificate_patterns(hostname: str, san_dns: List[str], common_names: List[str]) -> List[str]:
    matches = [pattern for pattern in san_dns if _hostname_matches_pattern(hostname, pattern)]
    matches.extend(pattern for pattern in common_names if _hostname_matches_pattern(hostname, pattern))
    return list(dict.fromkeys(matches))


def _evaluate_tls_confidence(
    tls_grade: str,
    hostname_match: bool,
    san_count: int,
    alpn_protocol: str,
    self_signed: bool,
    days_left: int | None,
    cert_age_days: int | None,
) -> Dict:
    score = 100
    reasons: List[str] = []

    if not hostname_match:
        score -= 45
        reasons.append("Hostname and certificate name alignment is weak")
    if san_count == 0:
        score -= 18
        reasons.append("SAN extension is missing")
    if not alpn_protocol:
        score -= 8
        reasons.append("ALPN negotiation is not observed")
    if self_signed:
        score -= 25
        reasons.append("Certificate appears self-signed")
    if days_left is not None and days_left < 14:
        score -= 10
        reasons.append("Certificate expiration window is tight")
    if cert_age_days is not None and cert_age_days < 7:
        score -= 8
        reasons.append("Certificate is very recently issued")
    if tls_grade in {"D", "F"}:
        score -= 20
        reasons.append("Overall TLS grade is weak")

    score = max(0, min(100, score))
    if score >= 80:
        level = "High"
    elif score >= 55:
        level = "Medium"
    else:
        level = "Low"

    if not reasons:
        reasons.append("No notable trust gaps were observed")

    if level == "High":
        if reasons and reasons[0] != "No notable trust gaps were observed":
            summary = "Strong certificate and protocol trust signals with minor gaps"
        else:
            summary = "Strong certificate and protocol trust signals"
    elif level == "Medium":
        summary = "Mixed trust signals; review recommended"
    else:
        summary = "Weak trust signals; remediation recommended"

    return {
        "level": level,
        "score": score,
        "summary": summary,
        "reasons": reasons,
    }


def _parse_caa_entry(entry: str) -> Dict[str, str]:
    raw = str(entry or "").strip()
    match = re.match(r'^(?:(\d+)\s+)?([A-Za-z0-9]+)\s+"?([^"]*)"?$', raw)
    if not match:
        return {"flags": "", "tag": "unknown", "value": raw, "raw": raw}
    return {
        "flags": (match.group(1) or "").strip(),
        "tag": match.group(2).lower().strip(),
        "value": (match.group(3) or "").strip(),
        "raw": raw,
    }


def _decode_punycode_hostname(hostname: str) -> str:
    labels = []
    for label in hostname.split("."):
        candidate = label.strip()
        if not candidate:
            continue
        if candidate.lower().startswith("xn--"):
            try:
                labels.append(candidate.encode("ascii").decode("idna"))
            except Exception:
                labels.append(candidate)
        else:
            labels.append(candidate)
    return ".".join(labels)


def _normalize_visual_token(value: str) -> str:
    mapped = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in value.lower())
    return re.sub(r"[^a-z0-9]", "", mapped)


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    if len(left) > len(right):
        left, right = right, left

    previous = list(range(len(left) + 1))
    for index_right, char_right in enumerate(right, start=1):
        current = [index_right]
        for index_left, char_left in enumerate(left, start=1):
            insert_cost = current[index_left - 1] + 1
            delete_cost = previous[index_left] + 1
            replace_cost = previous[index_left - 1] + (0 if char_left == char_right else 1)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _visual_confusion_assessment(hostname: str) -> Dict:
    decoded_hostname = _decode_punycode_hostname(hostname)
    core_label_source = decoded_hostname.split(".")[0] if decoded_hostname else ""
    core_label_normalized = _normalize_visual_token(core_label_source)
    token_candidates = [
        _normalize_visual_token(token)
        for token in re.split(r"[^0-9A-Za-z]+", core_label_source)
        if token
    ]

    candidate_labels: List[str] = []
    if core_label_normalized:
        candidate_labels.append(core_label_normalized)
    for token in token_candidates:
        if token and len(token) >= 3 and token not in candidate_labels:
            candidate_labels.append(token)

    best_brand = ""
    best_distance = None
    best_score = 0
    best_similarity = 0.0
    best_candidate_label = ""

    for candidate_label in candidate_labels:
        for brand in POPULAR_BRAND_TOKENS:
            distance = _levenshtein_distance(candidate_label, brand)
            baseline = max(len(candidate_label), len(brand), 1)
            similarity = max(0.0, 1.0 - (distance / baseline))
            length_gap = abs(len(candidate_label) - len(brand))

            if distance == 0:
                score = 10
            elif distance == 1 and baseline >= 5:
                score = 8
            elif distance == 2 and similarity >= 0.80 and length_gap <= 1:
                score = 7
            elif distance == 2 and similarity >= 0.72 and length_gap <= 2:
                score = 6
            elif similarity >= 0.70 and distance <= 3 and length_gap <= 1:
                score = 5
            else:
                score = max(0, round((similarity - 0.62) * 12))

            if best_distance is None or score > best_score or (score == best_score and distance < (best_distance or 0)):
                best_brand = brand
                best_distance = distance
                best_score = score
                best_similarity = similarity
                best_candidate_label = candidate_label

    if best_score < 5:
        best_brand = ""
        best_distance = None
        best_similarity = 0.0

    looks_like_domain = ""
    lookalike_assessment = ""
    is_brand_lookalike = False
    if best_brand:
        looks_like_domain = f"{best_brand}.com"
    if best_brand and best_score >= 8 and (best_distance is None or best_distance <= 1):
        is_brand_lookalike = True
        lookalike_assessment = f"Strong visual lookalike signal: looks like {looks_like_domain}"
    elif best_brand and best_score >= 7 and (best_distance is None or best_distance <= 2):
        is_brand_lookalike = True
        lookalike_assessment = f"Moderate visual lookalike signal: looks like {looks_like_domain}"
    elif best_brand and best_score >= 6:
        lookalike_assessment = f"Potential visual similarity to {looks_like_domain}"

    return {
        "decoded_hostname": decoded_hostname,
        "label": core_label_source,
        "normalized_label": core_label_normalized,
        "matched_label": best_candidate_label,
        "closest_brand": best_brand,
        "distance": best_distance,
        "score": max(0, min(10, best_score)),
        "similarity": round(best_similarity, 3),
        "looks_like_domain": looks_like_domain,
        "is_brand_lookalike": is_brand_lookalike,
        "lookalike_assessment": lookalike_assessment,
    }


def _image_average_hash(image_bytes: bytes, hash_size: int = 8) -> str | None:
    if Image is None:
        return None
    try:
        with Image.open(BytesIO(image_bytes)) as img:
            grayscale = img.convert("L").resize((hash_size, hash_size))
            pixels = grayscale.tobytes()
            if not pixels:
                return None
            avg_value = sum(pixels) / len(pixels)
            return "".join("1" if px >= avg_value else "0" for px in pixels)
    except Exception:
        return None


def _hamming_distance(left: str, right: str) -> int | None:
    if not left or not right or len(left) != len(right):
        return None
    return sum(ch1 != ch2 for ch1, ch2 in zip(left, right, strict=False))


def _fetch_screenshot_bytes(target_url: str, timeout: int = 14) -> Tuple[bytes | None, str]:
    api_url = SCREENSHOT_API_TEMPLATE.format(url=target_url)
    try:
        response = requests.get(api_url, timeout=timeout)
        if response.status_code >= 400:
            return None, f"screenshot_api_http_{response.status_code}"
        content_type = (response.headers.get("Content-Type", "") or "").lower()
        if "image" not in content_type:
            return None, "screenshot_non_image_response"
        body = response.content or b""
        if len(body) < 1024:
            return None, "screenshot_image_too_small"
        return body, "ok"
    except requests.RequestException:
        return None, "screenshot_api_unreachable"


def evaluate_screenshot_visual_similarity(final_url: str, visual_confusion: Dict) -> Dict:
    default_result = {
        "enabled": False,
        "status": "skipped",
        "signal_level": "Low",
        "detail": "Screenshot similarity not evaluated",
        "brand_domain": "",
        "target_hash": "",
        "brand_hash": "",
        "hamming_distance": None,
        "similarity_pct": 0.0,
        "screenshot_api": "thum.io",
    }

    if os.environ.get("WEBSCANNER_SKIP_SCREENSHOT_SIMILARITY", "").lower() == "1":
        default_result["detail"] = "Screenshot similarity disabled by environment"
        return default_result

    closest_brand = str(visual_confusion.get("closest_brand", "") or "").strip().lower()
    confusion_score = int(visual_confusion.get("score", 0) or 0)
    if not closest_brand or confusion_score < 7:
        default_result["detail"] = "No strong brand-lookalike candidate for screenshot comparison"
        return default_result

    canonical_domain = BRAND_CANONICAL_DOMAINS.get(closest_brand, f"{closest_brand}.com")
    brand_url = f"https://{canonical_domain}"

    if Image is None:
        return {
            **default_result,
            "enabled": True,
            "status": "unavailable",
            "brand_domain": canonical_domain,
            "detail": "Screenshot similarity unavailable (Pillow not installed)",
        }

    target_bytes, target_status = _fetch_screenshot_bytes(final_url)
    if not target_bytes:
        return {
            **default_result,
            "enabled": True,
            "status": target_status,
            "brand_domain": canonical_domain,
            "detail": "Could not capture target screenshot for visual comparison",
        }

    brand_bytes, brand_status = _fetch_screenshot_bytes(brand_url)
    if not brand_bytes:
        return {
            **default_result,
            "enabled": True,
            "status": brand_status,
            "brand_domain": canonical_domain,
            "detail": "Could not capture brand reference screenshot for visual comparison",
        }

    target_hash = _image_average_hash(target_bytes)
    brand_hash = _image_average_hash(brand_bytes)
    if not target_hash or not brand_hash:
        return {
            **default_result,
            "enabled": True,
            "status": "hash_failed",
            "brand_domain": canonical_domain,
            "detail": "Screenshot hashing failed",
        }

    distance = _hamming_distance(target_hash, brand_hash)
    if distance is None:
        return {
            **default_result,
            "enabled": True,
            "status": "hash_mismatch",
            "brand_domain": canonical_domain,
            "detail": "Screenshot hash mismatch",
        }

    hash_bits = len(target_hash)
    similarity_pct = round(max(0.0, 1.0 - (distance / max(hash_bits, 1))) * 100, 1)

    if similarity_pct >= 90.0 and distance <= 8:
        signal_level = "High"
        detail = f"Extremely strong phishing signal: screenshot visually similar to {canonical_domain} ({similarity_pct}% similarity)"
    elif similarity_pct >= 82.0 and distance <= 12:
        signal_level = "Medium"
        detail = f"Elevated phishing signal: screenshot visually similar to {canonical_domain} ({similarity_pct}% similarity)"
    else:
        signal_level = "Low"
        detail = f"Screenshot similarity to {canonical_domain} is not high ({similarity_pct}% similarity)"

    return {
        "enabled": True,
        "status": "ok",
        "signal_level": signal_level,
        "detail": detail,
        "brand_domain": canonical_domain,
        "target_hash": target_hash,
        "brand_hash": brand_hash,
        "hamming_distance": distance,
        "similarity_pct": similarity_pct,
        "screenshot_api": "thum.io",
    }


def detect_homoglyph_risk(hostname: str) -> Dict:
    if not hostname:
        return {
            "suspicious": False,
            "severity": "Low",
            "findings": [],
            "normalized_hint": "",
            "homoglyph_detected": False,
            "visual_confusion": {
                "score": 0,
                "closest_brand": "",
                "distance": None,
                "decoded_hostname": "",
                "normalized_label": "",
                "similarity": 0.0,
            },
        }

    scripts = set()
    mapped_chars: List[str] = []
    for ch in hostname:
        codepoint = ord(ch)
        if "a" <= ch.lower() <= "z":
            scripts.add("latin")
        elif 0x0400 <= codepoint <= 0x04FF:
            scripts.add("cyrillic")
        elif 0x0370 <= codepoint <= 0x03FF:
            scripts.add("greek")
        if ch in HOMOGLYPH_MAP:
            mapped_chars.append(ch)

    findings: List[str] = []
    severity = "Low"
    homoglyph_detected = False
    if len(scripts) > 1:
        findings.append("Mixed writing scripts detected in hostname")
        severity = "High"
        homoglyph_detected = True
    if mapped_chars:
        findings.append("Potential homoglyph characters detected")
        if severity != "High":
            severity = "Medium"
        homoglyph_detected = True

    normalized = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in hostname)
    confusion = _visual_confusion_assessment(hostname)
    confusion_score = int(confusion.get("score", 0) or 0)
    closest_brand = str(confusion.get("closest_brand", "") or "")
    distance = confusion.get("distance")

    return {
        "suspicious": bool(findings),
        "severity": severity,
        "findings": findings,
        "normalized_hint": normalized,
        "homoglyph_detected": homoglyph_detected,
        "visual_confusion": {
            "score": confusion_score,
            "closest_brand": closest_brand,
            "distance": distance,
            "decoded_hostname": confusion.get("decoded_hostname", ""),
            "normalized_label": confusion.get("normalized_label", ""),
            "matched_label": confusion.get("matched_label", ""),
            "similarity": confusion.get("similarity", 0.0),
            "looks_like_domain": confusion.get("looks_like_domain", ""),
            "is_brand_lookalike": confusion.get("is_brand_lookalike", False),
            "lookalike_assessment": confusion.get("lookalike_assessment", ""),
        },
    }


def lookup_email_auth_records(hostname: str, root_txt: List[str]) -> Dict:
    spf_present = any("v=spf1" in record.lower() for record in root_txt)
    dmarc_present = False
    dmarc_values: List[str] = []

    if hostname and dns is not None:
        resolver = dns.resolver.Resolver()
        try:
            answers = resolver.resolve(f"_dmarc.{hostname}", "TXT", lifetime=4)
            for answer in answers:
                joined = "".join(item.decode() for item in answer.strings)
                dmarc_values.append(joined)
            dmarc_present = any("v=dmarc1" in value.lower() for value in dmarc_values)
        except Exception:
            dmarc_present = False

    dmarc_record = ""
    dmarc_tags: Dict[str, str] = {}
    for value in dmarc_values:
        lowered = value.lower()
        if "v=dmarc1" not in lowered:
            continue
        dmarc_record = value
        parts = [segment.strip() for segment in value.split(";") if segment.strip()]
        for part in parts:
            if "=" not in part:
                continue
            key, tag_value = part.split("=", 1)
            dmarc_tags[key.strip().lower()] = tag_value.strip()
        break

    policy_raw = dmarc_tags.get("p", "").lower()
    pct_raw = dmarc_tags.get("pct", "100").strip()
    rua_raw = dmarc_tags.get("rua", "").strip()
    try:
        pct_value = int(pct_raw)
    except ValueError:
        pct_value = 100
    pct_value = max(0, min(100, pct_value))

    if not dmarc_present:
        effective_policy = "No DMARC policy"
        policy_strength = "None"
    elif policy_raw not in {"none", "quarantine", "reject"}:
        effective_policy = f"Unrecognized DMARC policy ({policy_raw or 'missing'})"
        policy_strength = "Weak"
    elif policy_raw == "none":
        effective_policy = f"Monitoring only (p=none, pct={pct_value})"
        policy_strength = "Weak"
    elif policy_raw == "quarantine":
        if pct_value < 100:
            effective_policy = f"Partial quarantine enforcement ({pct_value}%)"
            policy_strength = "Moderate"
        else:
            effective_policy = "Quarantine enforcement (100%)"
            policy_strength = "Moderate"
    else:
        if pct_value < 100:
            effective_policy = f"Partial reject enforcement ({pct_value}%)"
            policy_strength = "Moderate"
        else:
            effective_policy = "Full reject enforcement (100%)"
            policy_strength = "Strong"

    findings: List[str] = []
    severity = "Low"
    if not spf_present:
        findings.append("SPF record not found")
    if not dmarc_present:
        findings.append("DMARC record not found")
    elif policy_strength == "Weak":
        findings.append(f"DMARC policy is weak: {effective_policy}")
        if severity == "Low":
            severity = "Medium"
    if not spf_present and not dmarc_present:
        severity = "High"
    elif not spf_present or not dmarc_present:
        severity = "Medium"

    return {
        "spf_present": spf_present,
        "dmarc_present": dmarc_present,
        "dmarc_values": dmarc_values,
        "dmarc_analysis": {
            "record": dmarc_record,
            "tags": dmarc_tags,
            "policy": policy_raw,
            "pct": pct_value,
            "rua": rua_raw,
            "effective_policy": effective_policy,
            "policy_strength": policy_strength,
        },
        "severity": severity,
        "findings": findings,
    }


def google_safe_browsing_lookup(final_url: str, api_key: str) -> Dict:
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = (
        "{"
        '"client":{"clientId":"webscanner","clientVersion":"1.0"},'
        '"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],'
        '"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],'
        f'"threatEntries":[{{"url":"{final_url}"}}]'
        "}"
        "}"
    )

    try:
        response = requests.post(
            endpoint,
            data=payload,
            timeout=6,
        )
        if response.status_code >= 400:
            return {
                "listed": False,
                "status": f"error_http_{response.status_code}",
                "threat_types": [],
                "findings": [f"Google Safe Browsing request failed ({response.status_code})"],
            }

        response_text = response.text if response.content else ""
        has_matches = bool(re.search(r'"matches"\s*:\s*\[', response_text, flags=re.IGNORECASE))
        threat_types = sorted(set(re.findall(r'"threatType"\s*:\s*"([A-Z_]+)"', response_text)))
        matches = has_matches and bool(threat_types)
        if not matches:
            return {
                "listed": False,
                "status": "clean",
                "threat_types": [],
                "findings": [],
            }

        threat_text = ", ".join(threat_types) if threat_types else "unknown threat types"
        return {
            "listed": True,
            "status": "match",
            "threat_types": threat_types,
            "findings": [f"Google Safe Browsing matched: {threat_text}"],
        }
    except Exception:
        return {
            "listed": False,
            "status": "unavailable",
            "threat_types": [],
            "findings": ["Google Safe Browsing lookup unavailable"],
        }


def simple_phishing_lookup(final_url: str) -> Dict:
    parsed = urlparse(final_url)
    host = (parsed.hostname or "").lower()
    checked_sources: List[str] = ["local-blocklist"]
    source_hits: List[str] = []
    findings: List[str] = []
    listed = False

    if host in {domain.lower() for domain in LOCAL_PHISH_BLOCKLIST}:
        listed = True
        source_hits.append("local-blocklist")
        findings.append("Hostname matched local phishing blocklist")

    remote_lookup_allowed = os.environ.get("WEBSCANNER_SKIP_REMOTE_REPUTATION", "").lower() != "1"
    gsb_status = "not_checked"
    gsb_threat_types: List[str] = []
    gsb_key = os.environ.get("WEBSCANNER_GSB_API_KEY", "") or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if remote_lookup_allowed:
        if gsb_key:
            checked_sources.append("google-safe-browsing")
            gsb_result = google_safe_browsing_lookup(final_url, gsb_key)
            gsb_status = gsb_result.get("status", "unknown")
            gsb_threat_types = gsb_result.get("threat_types", [])
            if gsb_result.get("listed"):
                listed = True
                source_hits.append("google-safe-browsing")
                findings.extend(gsb_result.get("findings", []))
        else:
            gsb_status = "not_configured"

    urlhaus_status = "not_checked"
    should_check_urlhaus = remote_lookup_allowed and gsb_status != "match"
    if should_check_urlhaus:
        try:
            response = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": final_url},
                timeout=5,
            )
            checked_sources.append("urlhaus")
            response_text = (response.text or "").lower()
            query_status_match = re.search(r'"query_status"\s*:\s*"([a-z_]+)"', response_text)
            query_status = query_status_match.group(1) if query_status_match else ""
            urlhaus_status = query_status or "unknown"
            if query_status == "ok":
                listed = True
                source_hits.append("urlhaus")
                findings.append("URL found in URLhaus phishing/malware feed")
        except Exception:
            urlhaus_status = "unavailable"

    if "google-safe-browsing" in source_hits:
        primary_source = "google-safe-browsing"
        severity = "High"
    elif "urlhaus" in source_hits:
        primary_source = "urlhaus"
        severity = "High"
    elif "local-blocklist" in source_hits:
        primary_source = "local-blocklist"
        severity = "Medium"
    else:
        primary_source = "none"
        severity = "Low"

    return {
        "listed": listed,
        "severity": severity,
        "findings": findings,
        "sources": checked_sources,
        "source_hits": source_hits,
        "primary_source": primary_source,
        "google_safe_browsing_status": gsb_status,
        "google_safe_browsing_threat_types": gsb_threat_types,
        "urlhaus_status": urlhaus_status,
    }


def analyze_tls(final_url: str) -> Dict:
    parsed = urlparse(final_url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return {
            "supported": False,
            "detail": "HTTPS not in use",
            "severity": "Medium",
            "tls_grade": "N/A",
            "tls_score": 0,
            "findings": [],
        }

    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock, context.wrap_socket(
            sock, server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert() or {}
            tls_version = ssock.version() or ""
            cipher_info = ssock.cipher() or ("", "", 0)
            alpn_protocol = ssock.selected_alpn_protocol() or ""
        cipher_name = str(cipher_info[0]) if len(cipher_info) > 0 else ""
        cipher_bits = int(cipher_info[2]) if len(cipher_info) > 2 and isinstance(cipher_info[2], int) else 0
        not_after = cert.get("notAfter") if isinstance(cert, dict) else None
        not_before = cert.get("notBefore") if isinstance(cert, dict) else None
        not_after_str = not_after if isinstance(not_after, str) else ""
        not_before_str = not_before if isinstance(not_before, str) else ""
        expires_at = (
            datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z") if not_after_str else None
        )
        starts_at = (
            datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z") if not_before_str else None
        )
        now_utc = datetime.now(timezone.utc)
        days_left = (expires_at.replace(tzinfo=timezone.utc) - now_utc).days if expires_at else None
        cert_age_days = (now_utc - starts_at.replace(tzinfo=timezone.utc)).days if starts_at else None
        issuer = ", ".join(part[0][1] for part in cert.get("issuer", []) if part) if isinstance(cert, dict) else ""
        subject = ", ".join(part[0][1] for part in cert.get("subject", []) if part) if isinstance(cert, dict) else ""
        san_entries = cert.get("subjectAltName", []) if isinstance(cert, dict) else []
        san_dns: List[str] = []
        for entry in san_entries:
            if not isinstance(entry, tuple) or len(entry) != 2:
                continue
            kind, value = entry
            if kind == "DNS" and isinstance(value, str) and value:
                san_dns.append(value)

        findings: List[str] = []
        grade_score = 100

        severity = "Low"
        detail = "Certificate valid"
        if starts_at and starts_at.replace(tzinfo=timezone.utc) > now_utc:
            severity = "High"
            detail = "Certificate is not yet valid"
            findings.append("Certificate validity start date is in the future")
            grade_score -= 40
        elif cert_age_days is not None and cert_age_days < 14:
            if severity == "Low":
                severity = "Medium"
            findings.append("Certificate was issued very recently (<14 days)")
            grade_score -= 10
        if days_left is not None and days_left < 0:
            severity = "High"
            detail = "Certificate has expired"
            findings.append("Certificate is expired")
            grade_score -= 45
        elif days_left is not None and days_left < 10:
            severity = "High"
            detail = "Certificate expires very soon"
            findings.append("Certificate expiry is less than 10 days")
            grade_score -= 30
        elif days_left is not None and days_left < 30:
            severity = "Medium"
            detail = "Certificate expires soon"
            findings.append("Certificate expiry is less than 30 days")
            grade_score -= 15

        version_upper = tls_version.upper()
        if version_upper in {"TLSV1", "TLSV1.0", "TLSV1.1"}:
            severity = "High"
            findings.append(f"Legacy TLS protocol negotiated: {tls_version}")
            grade_score -= 35
        elif version_upper == "TLSV1.2" and severity != "High":
            findings.append("TLS 1.2 negotiated (acceptable, but TLS 1.3 preferred)")
            grade_score -= 10
        elif version_upper == "TLSV1.3":
            findings.append("TLS 1.3 negotiated")

        weak_cipher_tokens = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]
        if any(token in cipher_name.upper() for token in weak_cipher_tokens):
            severity = "High"
            findings.append(f"Weak cipher detected: {cipher_name}")
            grade_score -= 30
        elif cipher_bits and cipher_bits < 128:
            severity = "High"
            findings.append(f"Weak cipher bit length: {cipher_bits}")
            grade_score -= 30
        elif cipher_name:
            findings.append(f"Cipher negotiated: {cipher_name} ({cipher_bits} bits)")
            if cipher_bits < 256:
                grade_score -= 5

        subject_parts = cert.get("subject", []) if isinstance(cert, dict) else []
        common_names = [attr[0][1] for attr in subject_parts if attr and attr[0][0] == "commonName"]
        hostname_matches = _hostname_matches_certificate(hostname, san_dns, common_names) if hostname else False
        matched_patterns = _matching_certificate_patterns(hostname, san_dns, common_names) if hostname else []

        if not san_dns and not common_names:
            findings.append("Certificate SAN/CN names are missing")
            grade_score -= 20
        elif not san_dns and common_names:
            if severity == "Low":
                severity = "Medium"
            findings.append("Certificate SAN extension is missing; hostname validation relies on CN fallback")
            grade_score -= 10
        if not hostname_matches:
            if severity != "High":
                severity = "Medium"
            findings.append("Hostname did not exactly match certificate SAN/CN")
            grade_score -= 20
        elif matched_patterns:
            findings.append(f"Hostname matched certificate names: {', '.join(matched_patterns[:3])}")

        if alpn_protocol:
            findings.append(f"ALPN negotiated: {alpn_protocol}")
        else:
            findings.append("No ALPN protocol negotiated")
            grade_score -= 3

        is_self_signed = bool(subject and issuer and subject == issuer)
        if is_self_signed:
            if severity != "High":
                severity = "Medium"
            findings.append("Certificate appears self-signed")
            grade_score -= 20

        grade_score = max(0, min(100, grade_score))
        if grade_score >= 90:
            tls_grade = "A"
        elif grade_score >= 80:
            tls_grade = "B"
        elif grade_score >= 70:
            tls_grade = "C"
        elif grade_score >= 60:
            tls_grade = "D"
        else:
            tls_grade = "F"

        tls_confidence = _evaluate_tls_confidence(
            tls_grade=tls_grade,
            hostname_match=hostname_matches,
            san_count=len(san_dns),
            alpn_protocol=alpn_protocol,
            self_signed=is_self_signed,
            days_left=days_left,
            cert_age_days=cert_age_days,
        )

        return {
            "supported": True,
            "issuer": issuer,
            "subject": subject,
            "not_before": not_before or "",
            "not_after": not_after or "",
            "days_left": days_left,
            "cert_age_days": cert_age_days,
            "tls_version": tls_version,
            "alpn": alpn_protocol,
            "cipher": cipher_name,
            "cipher_bits": cipher_bits,
            "san_count": len(san_dns),
            "san_dns": san_dns,
            "common_names": common_names,
            "matched_patterns": matched_patterns,
            "hostname_match": hostname_matches,
            "self_signed": is_self_signed,
            "findings": findings,
            "severity": severity,
            "detail": detail,
            "tls_grade": tls_grade,
            "tls_score": grade_score,
            "tls_confidence": tls_confidence,
        }
    except Exception as error:
        return {
            "supported": False,
            "detail": f"TLS check failed: {error}",
            "severity": "High",
            "tls_grade": "F",
            "tls_score": 0,
            "tls_confidence": {
                "level": "Low",
                "score": 0,
                "summary": "TLS handshake failed",
                "reasons": [f"TLS handshake/inspection failed: {error}"],
            },
            "findings": [f"TLS handshake/inspection failed: {error}"],
        }


def analyze_csp(csp_value: str) -> Dict:
    if not csp_value:
        return {"severity": "High", "detail": "CSP missing", "directives": {}}

    directives: Dict[str, List[str]] = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        pieces = part.split()
        directives[pieces[0]] = pieces[1:]

    severity = "Low"
    issues: List[str] = []
    if "default-src" not in directives:
        severity = "Medium"
        issues.append("default-src missing")
    script_sources = directives.get("script-src", [])
    object_sources = directives.get("object-src", [])
    if "'unsafe-inline'" in script_sources or "'unsafe-eval'" in script_sources:
        severity = "Medium"
        issues.append("unsafe script sources allowed")
    if object_sources and "'none'" not in object_sources:
        severity = "Medium"
        issues.append("object-src not set to 'none'")

    detail = "; ".join(issues) if issues else "CSP appears reasonable"
    return {"severity": severity, "detail": detail, "directives": directives}


def _split_permissions_policy_directives(policy_value: str) -> List[str]:
    directives: List[str] = []
    current: List[str] = []
    in_quote = False
    paren_depth = 0

    for ch in policy_value:
        if ch == '"':
            in_quote = not in_quote
        elif ch == "(" and not in_quote:
            paren_depth += 1
        elif ch == ")" and not in_quote and paren_depth > 0:
            paren_depth -= 1

        if ch == "," and not in_quote and paren_depth == 0:
            token = "".join(current).strip()
            if token:
                directives.append(token)
            current = []
            continue
        current.append(ch)

    tail = "".join(current).strip()
    if tail:
        directives.append(tail)
    return directives


def analyze_permissions_policy(policy_value: str, report_only: bool = False) -> Dict:
    header_name = "Permissions-Policy-Report-Only" if report_only else "Permissions-Policy"
    raw = str(policy_value or "").strip()
    if not raw:
        detail = f"{header_name} not present"
        return {
            "present": False,
            "severity": "Low",
            "detail": detail,
            "directive_count": 0,
            "risky_directives": [],
            "malformed_directives": [],
        }

    directives = _split_permissions_policy_directives(raw)
    malformed_directives: List[str] = []
    risky_directives: List[str] = []

    for directive in directives:
        if "=" not in directive:
            malformed_directives.append(directive)
            continue
        name, value = directive.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name or not value:
            malformed_directives.append(directive)
            continue

        normalized_value = value.lower().replace(" ", "")
        if "*" in normalized_value:
            risky_directives.append(name)

    if malformed_directives:
        severity = "Medium"
        detail = f"{header_name} present but contains malformed directives"
    elif not directives:
        severity = "Medium"
        detail = f"{header_name} present but no directives were parsed"
    elif risky_directives:
        severity = "Medium"
        if report_only:
            detail = f"Report-only policy includes permissive wildcard directives: {', '.join(risky_directives[:3])}"
        else:
            detail = f"Policy includes permissive wildcard directives: {', '.join(risky_directives[:3])}"
    else:
        severity = "Low"
        if report_only:
            detail = f"Report-only policy present with {len(directives)} directive(s)"
        else:
            detail = f"Policy present with {len(directives)} directive(s)"

    return {
        "present": True,
        "severity": severity,
        "detail": detail,
        "directive_count": len(directives),
        "risky_directives": risky_directives,
        "malformed_directives": malformed_directives,
    }


def audit_cookies(response: requests.Response, is_https: bool) -> Dict:
    cookie_headers = get_set_cookie_headers(response)
    cookies: List[Dict] = []
    issues: List[str] = []
    total_cookies = 0
    secure_count = 0
    httponly_count = 0
    samesite_counts = {"strict": 0, "lax": 0, "none": 0, "missing": 0, "other": 0}
    secure_prefix_total = 0
    secure_prefix_compliant = 0
    host_prefix_total = 0
    host_prefix_compliant = 0

    for header in cookie_headers:
        jar = SimpleCookie()
        jar.load(header)
        for morsel in jar.values():
            total_cookies += 1
            flags = {
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"],
                "path": str(morsel["path"] or ""),
                "domain": str(morsel["domain"] or ""),
            }
            cookies.append({"name": morsel.key, "flags": flags})

            if flags["secure"]:
                secure_count += 1
            if flags["httponly"]:
                httponly_count += 1

            same_site = str(flags["samesite"] or "").strip().lower()
            if not same_site:
                samesite_counts["missing"] += 1
            elif same_site in {"strict", "lax", "none"}:
                samesite_counts[same_site] += 1
            else:
                samesite_counts["other"] += 1

            if is_https and not flags["secure"]:
                issues.append(f"Cookie {morsel.key} missing Secure")
            if not flags["httponly"]:
                issues.append(f"Cookie {morsel.key} missing HttpOnly")
            if not same_site:
                issues.append(f"Cookie {morsel.key} missing SameSite")
            elif same_site not in {"lax", "strict", "none"}:
                issues.append(f"Cookie {morsel.key} has non-standard SameSite value")
            if same_site == "none" and not flags["secure"]:
                issues.append(f"Cookie {morsel.key} uses SameSite=None without Secure")

            cookie_name = morsel.key
            if cookie_name.startswith("__Secure-"):
                secure_prefix_total += 1
                if not is_https:
                    issues.append(f"Cookie {morsel.key} violates __Secure- prefix requirements (must be set over HTTPS)")
                elif not flags["secure"]:
                    issues.append(f"Cookie {morsel.key} violates __Secure- prefix requirements (missing Secure)")
                else:
                    secure_prefix_compliant += 1

            if cookie_name.startswith("__Host-"):
                host_prefix_total += 1
                path_value = str(morsel["path"] or "")
                domain_value = str(morsel["domain"] or "")
                host_prefix_ok = is_https and flags["secure"] and path_value == "/" and not bool(domain_value)
                if not host_prefix_ok:
                    requirement_gaps = []
                    if not is_https:
                        requirement_gaps.append("HTTPS")
                    if not flags["secure"]:
                        requirement_gaps.append("Secure")
                    if path_value != "/":
                        requirement_gaps.append("Path=/")
                    if bool(domain_value):
                        requirement_gaps.append("no Domain attribute")
                    issues.append(
                        f"Cookie {morsel.key} violates __Host- prefix requirements ({', '.join(requirement_gaps)})"
                    )
                else:
                    host_prefix_compliant += 1

    severity = "Low"
    high_cookie_issue = any(
        issue for issue in issues
        if "SameSite=None without Secure" in issue
        or "violates __Host-" in issue
        or "violates __Secure-" in issue
    )
    if high_cookie_issue:
        severity = "High"
    elif any("missing Secure" in issue for issue in issues):
        severity = "Medium"
    if severity != "High" and len(issues) >= 3:
        severity = "Medium"

    summary = {
        "total": total_cookies,
        "secure": secure_count,
        "httponly": httponly_count,
        "samesite": samesite_counts,
        "secure_prefix_total": secure_prefix_total,
        "secure_prefix_compliant": secure_prefix_compliant,
        "host_prefix_total": host_prefix_total,
        "host_prefix_compliant": host_prefix_compliant,
    }
    return {"cookies": cookies, "issues": issues, "severity": severity, "summary": summary}


def _looks_like_real_csrf_token(value: str) -> bool:
    token = value.strip()
    if len(token) < 12:
        return False
    token_lower = token.lower()
    if token_lower in {
        "token",
        "csrf",
        "csrf_token",
        "placeholder",
        "test",
        "dummy",
        "dummy_token",
        "sample",
        "none",
        "null",
        "undefined",
        "changeme",
    }:
        return False
    if re.fullmatch(r"(?:token|csrf|csrf_token|placeholder|test|dummy|dummy_token|sample|none|null|undefined|changeme)[_-]?\d*", token_lower):
        return False
    classes = 0
    if re.search(r"[a-z]", token):
        classes += 1
    if re.search(r"[A-Z]", token):
        classes += 1
    if re.search(r"\d", token):
        classes += 1
    if re.search(r"[-_=.]", token):
        classes += 1
    return classes >= 2


def audit_forms(html: str, final_url: str, is_https: bool, response: requests.Response) -> Dict:
    soup = BeautifulSoup(html, "html.parser")
    findings: List[str] = []
    severity = "Low"
    csrf_evaluated_forms = 0
    csrf_missing_count = 0
    csrf_weak_count = 0
    csrf_token_values: List[str] = []

    page_meta_csrf = bool(
        soup.find("meta", attrs={"name": re.compile(r"csrf|xsrf", re.IGNORECASE), "content": True})
    )
    inline_js = "\n".join(script.get_text(" ", strip=True) for script in soup.find_all("script"))
    page_js_csrf = bool(re.search(r"csrf|xsrf", inline_js, re.IGNORECASE))

    cookie_headers = get_set_cookie_headers(response)
    any_samesite_cookie = False
    for header in cookie_headers:
        jar = SimpleCookie()
        jar.load(header)
        for morsel in jar.values():
            if morsel["samesite"]:
                any_samesite_cookie = True
                break
        if any_samesite_cookie:
            break

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        has_password = any(str(inp.get("type", "")).lower() == "password" for inp in inputs)
        method = str(form.get("method", "get")).strip().lower() or "get"
        state_changing = method in {"post", "put", "patch", "delete"}

        if not is_https and has_password:
            findings.append("Password form appears on non-HTTPS page")
            severity = "High"
        action = str(form.get("action", "")).strip()
        action_url = urljoin(final_url, action) if action else final_url
        if has_password and urlparse(action_url).scheme.lower() != "https":
            findings.append("Password form posts to non-HTTPS endpoint")
            severity = "High"

        if not state_changing:
            continue

        csrf_evaluated_forms += 1
        candidate_fields = []
        for inp in inputs:
            field_name = str(inp.get("name", "") or inp.get("id", "")).lower()
            field_type = str(inp.get("type", "")).lower()
            if field_type == "hidden" and any(hint in field_name for hint in CSRF_FIELD_HINTS):
                candidate_fields.append(inp)

        if not candidate_fields and not page_meta_csrf and not page_js_csrf:
            csrf_missing_count += 1
            findings.append("State-changing form missing detectable CSRF protection token")
            if severity != "High":
                severity = "Medium"
            continue

        real_token_found = False
        for field in candidate_fields:
            token_value = str(field.get("value", "")).strip()
            if not token_value:
                continue
            if _looks_like_real_csrf_token(token_value):
                real_token_found = True
                csrf_token_values.append(token_value)

        if candidate_fields and not real_token_found:
            csrf_weak_count += 1
            findings.append("CSRF token field present but value looks weak/static/placeholder")
            if severity == "Low":
                severity = "Medium"

    if csrf_evaluated_forms > 0 and not any_samesite_cookie:
        findings.append("No SameSite cookie observed; CSRF defense-in-depth may be weak")
        if severity == "Low":
            severity = "Medium"

    return {
        "findings": findings,
        "severity": severity,
        "csrf_validation": {
            "forms_evaluated": csrf_evaluated_forms,
            "missing_token_forms": csrf_missing_count,
            "weak_token_forms": csrf_weak_count,
            "has_samesite_cookie": any_samesite_cookie,
            "page_level_csrf_signal": page_meta_csrf or page_js_csrf,
        },
    }


def analyze_resources(html: str, final_url: str, is_https: bool) -> Dict:
    soup = BeautifulSoup(html, "html.parser")
    external_js: List[str] = []
    external_css: List[str] = []
    external_fonts: List[str] = []
    mixed_content: List[str] = []
    missing_sri: List[str] = []

    for script in soup.find_all("script", src=True):
        src = str(script.get("src", "")).strip()
        if not src:
            continue
        absolute = urljoin(final_url, src)
        if is_external_url(final_url, absolute):
            external_js.append(absolute)
        if is_https and absolute.startswith("http://"):
            mixed_content.append(absolute)
        if is_external_url(final_url, absolute) and not script.get("integrity"):
            missing_sri.append(absolute)

    for link in soup.find_all("link", href=True):
        rel_attr = link.get("rel")
        if isinstance(rel_attr, list):
            rel = " ".join(str(item) for item in rel_attr).lower()
        elif isinstance(rel_attr, str):
            rel = rel_attr.lower()
        else:
            rel = ""
        href = str(link.get("href", "")).strip()
        if not href:
            continue
        absolute = urljoin(final_url, href)
        if "stylesheet" in rel:
            if is_external_url(final_url, absolute):
                external_css.append(absolute)
            if is_https and absolute.startswith("http://"):
                mixed_content.append(absolute)
        if "preload" in rel and "font" in str(link.get("as", "")):
            external_fonts.append(absolute)

    severity = "Low"
    if mixed_content:
        severity = "High"
    elif missing_sri:
        severity = "Medium"

    return {
        "external_js": external_js,
        "external_css": external_css,
        "external_fonts": external_fonts,
        "mixed_content": mixed_content,
        "missing_sri": missing_sri,
        "severity": severity,
    }


def analyze_robots(base_url: str, manager: RequestManager) -> Dict:
    robots_url = urljoin(base_url, "/robots.txt")
    resp = manager.get(robots_url)
    if not resp or resp.status_code != 200:
        return {"found": False, "disallowed": [], "sensitive": []}

    disallowed = []
    sensitive = []
    for line in resp.text.splitlines():
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
                if any(token in path.lower() for token in ["admin", "backup", "db", "config", "secret"]):
                    sensitive.append(path)

    return {"found": True, "disallowed": disallowed, "sensitive": sensitive}


def top_risks_summary(sections: List[Tuple[str, str, str]]) -> List[str]:
    order = {"High": 0, "Medium": 1, "Low": 2}
    ranked = sorted(sections, key=lambda item: order.get(item[1], 3))
    return [f"{name}: {level} - {detail}" for name, level, detail in ranked[:3]]


def active_light_probe(base_url: str, manager: RequestManager) -> Dict:
    findings: List[Dict] = []

    options_resp = manager.request("OPTIONS", base_url, timeout=8, allow_redirects=False, use_cache=False)
    if options_resp is not None:
        allow_hdr = options_resp.headers.get("Allow", "")
        risky_verbs = [verb for verb in ["PUT", "DELETE", "TRACE", "CONNECT"] if verb in allow_hdr.upper()]
        if risky_verbs:
            findings.append(
                {
                    "check": "HTTP Methods",
                    "severity": "Medium",
                    "detail": f"Server advertises potentially risky methods: {', '.join(risky_verbs)}",
                }
            )

    trace_resp = manager.request("TRACE", base_url, timeout=8, allow_redirects=False, use_cache=False)
    if trace_resp is not None and trace_resp.status_code < 400:
        trace_echo = trace_resp.text[:300].upper()
        trace_detail = "TRACE appears enabled"
        if "TRACE" in trace_echo and "HTTP/" in trace_echo:
            trace_detail = "TRACE appears enabled and request data may be echoed"
        findings.append(
            {
                "check": "TRACE Method",
                "severity": "Medium",
                "detail": trace_detail,
            }
        )

    cors_resp = manager.request(
        "GET",
        base_url,
        timeout=8,
        allow_redirects=False,
        use_cache=False,
        headers={"Origin": "https://example.org"},
    )
    if cors_resp is not None:
        acao = cors_resp.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
        if acao == "*" and acac == "true":
            findings.append(
                {
                    "check": "CORS Policy",
                    "severity": "High",
                    "detail": "CORS allows wildcard origin with credentials",
                }
            )
        elif acao == "*":
            findings.append(
                {
                    "check": "CORS Policy",
                    "severity": "Medium",
                    "detail": "CORS allows wildcard origin",
                }
            )

    probe_marker = "copilot_probe_token_2468"
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)
    params["probe"] = [probe_marker]
    probe_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
    probe_resp = manager.get(probe_url, timeout=8, allow_redirects=True)
    if probe_resp is not None and probe_marker in probe_resp.text:
        findings.append(
            {
                "check": "Input Reflection",
                "severity": "Medium",
                "detail": "Probe query token reflected in response",
            }
        )

    current_params = parse_qs(parsed.query)
    redirect_targets = [key for key in current_params if key.lower() in REDIRECT_PARAM_NAMES]
    for key in redirect_targets[:2]:
        tmp_params = parse_qs(parsed.query)
        tmp_params[key] = ["https://example.org"]
        test_url = parsed._replace(query=urlencode(tmp_params, doseq=True)).geturl()
        redir_resp = manager.get(test_url, timeout=8, allow_redirects=False)
        if redir_resp is not None and 300 <= redir_resp.status_code < 400:
            loc = redir_resp.headers.get("Location", "")
            if "example.org" in loc:
                findings.append(
                    {
                        "check": "Redirect Handling",
                        "severity": "Medium",
                        "detail": f"Redirect parameter '{key}' may allow external redirect",
                    }
                )

    if not findings:
        findings.append(
            {
                "check": "Active Light Probe",
                "severity": "Low",
                "detail": "No major issues detected from safe active probes",
            }
        )

    overall = max_severity([item["severity"] for item in findings])
    return {"findings": findings, "overall": overall}


def gather_dns_records(hostname: str) -> Dict:
    records = {"a": [], "mx": [], "ns": [], "txt": [], "caa": [], "resolver_available": dns is not None}
    if not hostname or dns is None:
        return records
    resolver = dns.resolver.Resolver()

    def resolve_record(record_type: str) -> List[str]:
        try:
            answers = resolver.resolve(hostname, record_type, lifetime=4)
            if record_type == "TXT":
                return ["".join(item.decode() for item in answer.strings) for answer in answers]
            return [str(answer).rstrip(".") for answer in answers]
        except Exception:
            return []

    for rtype in ["A", "MX", "NS", "TXT", "CAA"]:
        records[rtype.lower()] = resolve_record(rtype)
    return records


def gather_whois_intel(hostname: str) -> Dict:
    result = {
        "available": whois is not None,
        "registrar": "",
        "creation_date": "",
        "days_old": None,
        "new_domain": False,
    }
    if not hostname or whois is None:
        return result
    try:
        info = whois.whois(hostname)
        if isinstance(info, dict):
            creation = info.get("creation_date")
            registrar = info.get("registrar")
        else:
            creation = getattr(info, "creation_date", None)
            registrar = getattr(info, "registrar", "")
        if isinstance(creation, list) and creation:
            creation = creation[0]
        if isinstance(creation, datetime):
            creation_utc = creation if creation.tzinfo else creation.replace(tzinfo=timezone.utc)
            days_old = (datetime.now(timezone.utc) - creation_utc).days
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["days_old"] = days_old
            result["new_domain"] = days_old < 90
        result["registrar"] = str(registrar or "")
    except Exception:
        pass
    return result


def analyze_domain_intelligence(final_url: str) -> Dict:
    host = urlparse(final_url).hostname or ""
    dns_records = gather_dns_records(host)
    whois_info = gather_whois_intel(host)
    homoglyph = detect_homoglyph_risk(host)
    email_auth = lookup_email_auth_records(host, dns_records.get("txt", []))

    findings: List[str] = []
    severity = "Low"
    host_is_ip = False
    if host:
        try:
            ip_obj = ipaddress.ip_address(host)
            host_is_ip = True
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                findings.append("Host is a private/reserved IP address")
                severity = "High"
            else:
                findings.append("Host uses a raw IP address")
                if severity != "High":
                    severity = "Medium"
        except ValueError:
            host_is_ip = False

    if "xn--" in host:
        findings.append("Punycode domain label detected")
        if severity == "Low":
            severity = "Medium"

    if homoglyph["suspicious"]:
        findings.extend(homoglyph["findings"])
        if homoglyph["severity"] == "High":
            severity = "High"
        elif severity == "Low":
            severity = "Medium"

    visual_confusion = homoglyph.get("visual_confusion", {})
    screenshot_similarity = evaluate_screenshot_visual_similarity(final_url, visual_confusion)
    confusion_score = int(visual_confusion.get("score", 0) or 0)
    confusion_distance = visual_confusion.get("distance")
    if (
        confusion_score >= 8
        and visual_confusion.get("closest_brand")
        and (confusion_distance is None or confusion_distance <= 1)
    ):
        findings.append(
            f"High visual brand confusion score ({confusion_score}/10) vs '{visual_confusion.get('closest_brand')}'"
        )
        severity = "High"
    elif (
        confusion_score >= 7
        and visual_confusion.get("closest_brand")
        and (confusion_distance is None or confusion_distance <= 2)
    ):
        findings.append(
            f"Moderate visual brand confusion score ({confusion_score}/10) vs '{visual_confusion.get('closest_brand')}'"
        )
        if severity == "Low":
            severity = "Medium"
    elif confusion_score >= 6 and homoglyph.get("homoglyph_detected") and severity == "Low":
        findings.append(
            f"Moderate visual confusion with mixed-script/homoglyph context ({confusion_score}/10)"
        )
        severity = "Medium"

    if visual_confusion.get("is_brand_lookalike"):
        findings.append(visual_confusion.get("lookalike_assessment", "Visual brand lookalike detected"))
        if confusion_score >= 8:
            severity = "High"
        elif severity == "Low":
            severity = "Medium"

    screenshot_signal_level = screenshot_similarity.get("signal_level", "Low")
    if screenshot_signal_level == "High":
        findings.append(str(screenshot_similarity.get("detail", "Strong screenshot visual similarity detected")))
        severity = "High"
    elif screenshot_signal_level == "Medium":
        findings.append(str(screenshot_similarity.get("detail", "Elevated screenshot visual similarity detected")))
        if severity == "Low":
            severity = "Medium"

    if host and not host_is_ip and not dns_records.get("a"):
        findings.append("No A records resolved")
        severity = "High"
    if whois_info.get("new_domain"):
        findings.append("Domain appears recently registered")
        if severity != "High":
            severity = "Medium"
    if not host_is_ip and not dns_records.get("mx"):
        findings.append("No MX record detected")

    caa_records = dns_records.get("caa", [])
    caa_parsed = [_parse_caa_entry(item) for item in caa_records]
    caa_tags = [item.get("tag", "") for item in caa_parsed]
    caa_present = bool(caa_records)
    caa_signal_level = "Low"
    caa_signal_detail = "CAA present or not required for assessed context"
    if host and not host_is_ip and not caa_present:
        caa_signal_level = "High"
        caa_signal_detail = "CAA record missing (very strong phishing infrastructure signal)"
        findings.append("CAA record not found (very strong phishing infrastructure signal)")
        severity = "High"
    elif caa_present and not any(tag in {"issue", "issuewild"} for tag in caa_tags):
        caa_signal_level = "Medium"
        caa_signal_detail = "CAA record exists but lacks explicit issue/issuewild authorization"
        findings.append("CAA exists but no explicit issue/issuewild authorization tags found")

    if email_auth["severity"] == "High":
        severity = "High"
    elif email_auth["severity"] == "Medium" and severity == "Low":
        severity = "Medium"
    findings.extend(email_auth["findings"])

    return {
        "hostname": host,
        "dns": dns_records,
        "whois": whois_info,
        "homoglyph": homoglyph,
        "visual_confusion": visual_confusion,
        "screenshot_similarity": screenshot_similarity,
        "email_auth": email_auth,
        "caa_present": caa_present,
        "caa_records": caa_records,
        "caa_tags": caa_tags,
        "caa_evaluation": {
            "has_issue_authorization": any(tag in {"issue", "issuewild"} for tag in caa_tags),
            "has_iodef": "iodef" in caa_tags,
            "record_count": len(caa_records),
            "signal_level": caa_signal_level,
            "signal_detail": caa_signal_detail,
        },
        "findings": findings,
        "severity": severity,
    }


def analyze_redirect_chain(response: requests.Response) -> Dict:
    hops = []
    previous = response.request.url if response.request else ""
    severity = "Low"
    findings: List[str] = []
    seen_urls = {previous} if previous else set()
    cross_domain_count = 0

    for hist in response.history:
        location = hist.headers.get("Location", "")
        next_url = urljoin(hist.url, location) if location else hist.url
        cross_domain = urlparse(previous).netloc != urlparse(next_url).netloc
        downgraded = urlparse(previous).scheme == "https" and urlparse(next_url).scheme == "http"
        hops.append(
            {
                "from": previous,
                "to": next_url,
                "status": hist.status_code,
                "cross_domain": cross_domain,
                "downgraded": downgraded,
            }
        )
        if downgraded:
            severity = "High"
            findings.append("HTTPS to HTTP downgrade detected in redirect chain")
        elif cross_domain and severity != "High":
            severity = "Medium"
            cross_domain_count += 1
        if next_url in seen_urls:
            findings.append("Potential redirect loop/revisit detected")
            if severity != "High":
                severity = "Medium"
        seen_urls.add(next_url)
        previous = next_url

    hop_count = len(hops)
    if hop_count > 5:
        severity = "High"
        findings.append("Excessive redirect depth (>5 hops)")
    elif hop_count > 3 and severity != "High":
        severity = "Medium"
        findings.append("Long redirect chain (>3 hops)")

    if cross_domain_count >= 2 and severity != "High":
        severity = "Medium"
        findings.append("Multiple cross-domain redirect hops detected")

    return {
        "hops": hops,
        "severity": severity,
        "findings": findings,
        "hop_count": hop_count,
        "cross_domain_hops": cross_domain_count,
    }


def build_sensitive_probe_paths() -> List[str]:
    paths = set(SENSITIVE_PATHS)
    for base in SENSITIVE_BACKUP_BASES:
        for suffix in SENSITIVE_BACKUP_SUFFIXES:
            paths.add(f"/{base}{suffix}")
    return sorted(paths)


def apply_false_positive_suppressors(result: Dict):
    resources = result.get("resources", {})
    safe_missing_sri = [
        src for src in resources.get("missing_sri", []) if any(token in src for token in SAFE_CDN_TOKENS)
    ]
    if safe_missing_sri:
        resources["missing_sri"] = [s for s in resources.get("missing_sri", []) if s not in safe_missing_sri]
        resources.setdefault("notes", []).append("Downgraded SRI warnings for trusted CDN sources")
        if not resources.get("missing_sri") and resources.get("severity") == "Medium":
            resources["severity"] = "Low"


def estimate_output_accuracy(result: Dict) -> Dict:
    app_confidence = int(result.get("app_risk", {}).get("confidence_score", 0) or 0)
    tls_confidence = int(result.get("tls", {}).get("tls_confidence", {}).get("score", 0) or 0)

    module_checks = [
        bool(result.get("security")),
        bool(result.get("phishing")),
        bool(result.get("app_risk")),
        bool(result.get("active_probe")),
        bool(result.get("sensitive_exposure")),
        bool(result.get("tls")),
        bool(result.get("domain_intel")),
        bool(result.get("redirect_chain")),
        bool(result.get("reputation_lookup")),
    ]
    completed_checks = sum(1 for ok in module_checks if ok)
    check_coverage = round((completed_checks / len(module_checks)) * 100, 1) if module_checks else 0.0

    security = result.get("security", {})
    tls = result.get("tls", {})
    transport_reliability = 100.0
    adjustments: List[str] = []

    if not security.get("is_https"):
        transport_reliability -= 20
        adjustments.append("target is not HTTPS")
    if not tls.get("supported"):
        transport_reliability -= 15
        adjustments.append("TLS details unavailable")
    if tls.get("supported") and not tls.get("hostname_match"):
        transport_reliability -= 20
        adjustments.append("certificate hostname mismatch")
    if tls.get("supported") and tls.get("self_signed"):
        transport_reliability -= 10
        adjustments.append("self-signed certificate")
    if result.get("ssl_fallback_used"):
        transport_reliability -= 8
        adjustments.append("SSL verification was bypassed")

    transport_reliability = max(0.0, min(100.0, transport_reliability))

    status_code = int(result.get("status_code", 0) or 0)
    execution_health = 100.0
    if status_code >= 500:
        execution_health -= 15
        adjustments.append("server returned 5xx response")
    elif status_code >= 400:
        execution_health -= 8
        adjustments.append("target returned 4xx response")
    elif status_code in {0, 301, 302, 307, 308}:
        execution_health -= 3

    if not result.get("ok"):
        execution_health -= 25
        adjustments.append("scan did not complete successfully")

    execution_health = max(0.0, min(100.0, execution_health))

    consistency_score = round((app_confidence * 0.4) + (tls_confidence * 0.6), 1)
    percentage = round(
        max(
            0.0,
            min(
                100.0,
                (check_coverage * 0.45) + (transport_reliability * 0.35) + (execution_health * 0.10) + (consistency_score * 0.10),
            ),
        ),
        1,
    )
    if percentage >= 90:
        level = "High"
        summary = "Result confidence is strong for this heuristic model."
    elif percentage >= 65:
        level = "Medium"
        summary = "Result confidence is moderate; validate critical findings manually."
    else:
        level = "Low"
        summary = "Result confidence is limited; corroborate with additional tools."

    return {
        "percentage": percentage,
        "level": level,
        "summary": summary,
        "inputs": {
            "app_confidence": app_confidence,
            "tls_confidence": tls_confidence,
            "check_coverage": check_coverage,
            "transport_reliability": round(transport_reliability, 1),
            "execution_health": round(execution_health, 1),
            "consistency_score": consistency_score,
        },
        "adjustments": adjustments,
    }


def weighted_overall_score(result: Dict, weight_profile: str = "balanced") -> Dict:
    severity_scores = {"Low": 0, "Medium": 55, "High": 100}
    profile_key = weight_profile if weight_profile in WEIGHT_PROFILES else "balanced"
    weights = WEIGHT_PROFILES[profile_key]
    profile_meta = WEIGHT_PROFILE_METADATA.get(profile_key, {})

    components = {
        "security": result["security"]["vulnerability_level"],
        "security_extras": result["security_extras"],
        "phishing": result["phishing"]["level"],
        "application": result["app_risk"]["overall"],
        "active_probe": result.get("active_probe", {}).get("overall", "Low"),
        "exposure": result["sensitive_exposure"]["overall"],
        "domain": result.get("domain_intel", {}).get("severity", "Low"),
        "redirect": result.get("redirect_chain", {}).get("severity", "Low"),
        "reputation": result.get("reputation_lookup", {}).get("severity", "Low"),
    }

    component_scores = {
        name: severity_scores.get(level, 0)
        for name, level in components.items()
    }
    contributions = {
        name: round(component_scores[name] * weights[name], 2)
        for name in components
    }

    weighted = sum(contributions.values())
    total_weight = sum(weights.values())
    normalized_score = round(weighted / total_weight, 1) if total_weight > 0 else 0.0
    if normalized_score >= 70:
        band = "High"
        risk_label = "Elevated"
        outlook = "Risk concentration is high; prioritize remediation now."
    elif normalized_score >= 40:
        band = "Medium"
        risk_label = "Guarded"
        outlook = "Mixed risk posture; targeted hardening is recommended."
    else:
        band = "Low"
        risk_label = "Stable"
        outlook = "Risk posture is relatively stable for this heuristic model."

    ordered_drivers = sorted(contributions.items(), key=lambda item: item[1], reverse=True)
    top_drivers = []
    for name, contribution in ordered_drivers:
        if contribution <= 0:
            continue
        level = components.get(name, "Low")
        top_drivers.append(f"{name.replace('_', ' ').title()} ({level}) contributes {contribution:.1f}")
        if len(top_drivers) == 3:
            break

    dominant_component = ordered_drivers[0][0] if ordered_drivers else ""
    dominant_impact = round(float(ordered_drivers[0][1]), 2) if ordered_drivers else 0.0

    risk_pressure = round(
        sum(weights[name] for name, level in components.items() if level in {"Medium", "High"}) * 100,
        1,
    )

    component_rankings = []
    for name, impact in ordered_drivers:
        component_rankings.append(
            {
                "component": name,
                "level": components.get(name, "Low"),
                "weight_pct": round(float(weights.get(name, 0.0)) * 100, 1),
                "impact": round(float(impact), 2),
            }
        )

    high_count = sum(1 for level in components.values() if level == "High")
    medium_count = sum(1 for level in components.values() if level == "Medium")

    return {
        "score": normalized_score,
        "band": band,
        "risk_label": risk_label,
        "profile": profile_key,
        "profile_label": WEIGHT_PROFILE_LABELS.get(profile_key, profile_key.title()),
        "profile_focus": profile_meta.get("focus", ""),
        "profile_best_for": profile_meta.get("best_for", ""),
        "profile_description": profile_meta.get("description", ""),
        "components": components,
        "weights": weights,
        "component_scores": component_scores,
        "contributions": contributions,
        "top_drivers": top_drivers,
        "component_rankings": component_rankings,
        "dominant_component": dominant_component,
        "dominant_impact": dominant_impact,
        "risk_pressure": risk_pressure,
        "outlook": outlook,
        "high_count": high_count,
        "medium_count": medium_count,
    }


def _extract_previous_levels_from_markdown(markdown_text: str) -> Dict[str, str]:
    levels: Dict[str, str] = {}
    in_risk_section = False
    for raw_line in markdown_text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            in_risk_section = line.lower() == "## risk levels"
            continue
        if not in_risk_section or not line.startswith("- ") or ":" not in line:
            continue
        key, value = line[2:].split(":", 1)
        levels[key.strip().lower()] = value.strip()
    return levels


def _normalize_previous_report(markdown_text: str) -> Dict:
    markdown_levels = _extract_previous_levels_from_markdown(markdown_text)
    overview: Dict[str, str] = {}
    for raw_line in markdown_text.splitlines():
        line = raw_line.strip()
        if line.startswith("- ") and ":" in line:
            key, value = line[2:].split(":", 1)
            overview[key.strip().lower()] = value.strip()
    return {
        "security": {"vulnerability_level": markdown_levels.get("security")},
        "phishing": {"level": markdown_levels.get("phishing")},
        "app_risk": {"overall": markdown_levels.get("application")},
        "sensitive_exposure": {"overall": markdown_levels.get("sensitive exposure")},
        "overall_verdict": overview.get("verdict", ""),
        "weighted_model": {"score": None},
    }


def compute_diff_with_previous(current: Dict, previous_path: str) -> Dict:
    if not previous_path:
        return {"enabled": False, "changes": []}
    try:
        with open(previous_path, "r", encoding="utf-8") as file:
            raw_text = file.read()
        prev = _normalize_previous_report(raw_text)
    except Exception:
        return {"enabled": True, "changes": ["Previous report not readable"]}

    changes = []
    keys = [
        ("security.vulnerability_level", current["security"]["vulnerability_level"], prev.get("security", {}).get("vulnerability_level")),
        ("phishing.level", current["phishing"]["level"], prev.get("phishing", {}).get("level")),
        ("app_risk.overall", current["app_risk"]["overall"], prev.get("app_risk", {}).get("overall")),
        ("sensitive_exposure.overall", current["sensitive_exposure"]["overall"], prev.get("sensitive_exposure", {}).get("overall")),
    ]
    for name, now_val, prev_val in keys:
        if prev_val is not None and prev_val != now_val:
            changes.append(f"{name} changed: {prev_val} -> {now_val}")
    prev_verdict = prev.get("overall_verdict")
    if prev_verdict and prev_verdict != current.get("overall_verdict"):
        changes.append(f"overall_verdict changed: {prev_verdict} -> {current.get('overall_verdict')}")
    if not changes:
        changes.append("No major level changes from previous report")
    return {"enabled": True, "changes": changes}


def max_severity(levels: List[str]) -> str:
    priority = {"Low": 1, "Medium": 2, "High": 3}
    if not levels:
        return "Low"
    return max(levels, key=lambda item: priority.get(item, 1))


def severity_label(level: str) -> str:
    if level == "High":
        return "🔴 High"
    if level == "Medium":
        return "🟠 Medium"
    return "🟢 Low"


def severity_rich_style(level: str) -> str:
    if level == "High":
        return "bold red"
    if level == "Medium":
        return "bold yellow"
    return "bold green"


def is_external_url(base_url: str, candidate: str) -> bool:
    if not candidate:
        return False
    if candidate.startswith("//"):
        candidate = f"{urlparse(base_url).scheme}:{candidate}"
    parsed = urlparse(candidate)
    if not parsed.scheme:
        return False
    return bool(parsed.netloc) and parsed.netloc != urlparse(base_url).netloc


def score_to_severity(score: int) -> str:
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def looks_like_user_supplied_token(value: str) -> bool:
    if len(value) < 5:
        return False
    if re.search(r"[@<>%{}()'\";=:/\\]", value):
        return True
    return bool(re.search(r"\d", value) and re.search(r"[a-zA-Z]", value))


def evaluate_application_indicators(final_url: str, response: requests.Response) -> Dict:
    html = response.text
    parsed = urlparse(final_url)
    query_params = parse_qs(parsed.query)
    findings: List[Dict] = []
    risk_points = 0

    reflected_params: List[str] = []
    for key, values in query_params.items():
        for value in values:
            value = value.strip()
            if not value or not looks_like_user_supplied_token(value):
                continue
            reflected_count = html.count(value)
            if reflected_count == 0:
                continue
            appears_in_form_value = (
                f'value="{value}"' in html or f"value='{value}'" in html
            )
            appears_in_anchor = f"href=\"{value}\"" in html or f"href='{value}'" in html
            if reflected_count <= 5 and not appears_in_form_value and not appears_in_anchor:
                reflected_params.append(key)
                break
    if reflected_params:
        findings.append(
            {
                "category": "Reflected Input",
                "severity": "Medium",
                "detail": "Query parameters reflected in response body: " + ", ".join(sorted(set(reflected_params))),
            }
        )
        risk_points += 2

    soup = BeautifulSoup(html, "html.parser")
    inline_js = "\n".join(script.get_text(" ", strip=True) for script in soup.find_all("script"))
    source_hits = len(DOM_SOURCE_PATTERN.findall(inline_js))
    sink_hits = len(DOM_SINK_PATTERN.findall(inline_js))
    if source_hits and sink_hits:
        dom_severity = "High" if sink_hits >= 2 else "Medium"
        findings.append(
            {
                "category": "DOM XSS Surface",
                "severity": dom_severity,
                "detail": f"JS source/sink patterns found (sources={source_hits}, sinks={sink_hits})",
            }
        )
        risk_points += 3 if dom_severity == "High" else 2

    redirect_hits: List[str] = []
    for key, values in query_params.items():
        if key.lower() not in REDIRECT_PARAM_NAMES:
            continue
        for value in values:
            lowered = value.strip().lower()
            if lowered.startswith(("javascript:", "//", "\\\\")):
                redirect_hits.append(f"{key}={value}")
                continue
            if lowered.startswith(("http://", "https://")) and is_external_url(final_url, value):
                redirect_hits.append(f"{key}={value}")
    if redirect_hits:
        findings.append(
            {
                "category": "Open Redirect Surface",
                "severity": "Medium",
                "detail": "Redirect-like parameters contain external/scheme values",
            }
        )
        risk_points += 2

    form_redirect_hits = 0
    for form in soup.find_all("form"):
        for field in form.find_all(["input", "textarea"]):
            field_name = str(field.get("name", "")).lower()
            field_value = str(field.get("value", "")).strip()
            if field_name in REDIRECT_PARAM_NAMES and is_external_url(final_url, field_value):
                form_redirect_hits += 1
    if form_redirect_hits:
        findings.append(
            {
                "category": "Redirect Field",
                "severity": "Medium",
                "detail": f"Form contains {form_redirect_hits} external redirect-like field(s)",
            }
        )
        risk_points += 2

    header_anomalies = []
    for key, value in response.headers.items():
        if "\n" in value or "\r" in value:
            header_anomalies.append(key)
    if header_anomalies:
        findings.append(
            {
                "category": "Header Anomaly",
                "severity": "High",
                "detail": "Unexpected newline characters in headers: " + ", ".join(header_anomalies),
            }
        )
        risk_points += 3

    if not findings:
        findings.append(
            {
                "category": "Passive Analysis",
                "severity": "Low",
                "detail": "No strong passive application-layer indicators detected",
            }
        )

    severity_points = {"Low": 1, "Medium": 2, "High": 3}
    evidence_weight = sum(severity_points.get(item["severity"], 1) for item in findings)
    combined_score = risk_points + evidence_weight
    overall = score_to_severity(combined_score)
    if any(item["severity"] == "High" for item in findings):
        overall = "High"

    confidence_score = min(100, 10 + combined_score * 8)

    return {
        "findings": findings,
        "overall": overall,
        "confidence_score": confidence_score,
    }


def audit_security_headers(response: requests.Response) -> Dict:
    headers = {name.lower(): value for name, value in response.headers.items()}
    is_https = urlparse(response.url).scheme.lower() == "https"
    csp_analysis = analyze_csp(headers.get("content-security-policy", ""))
    permissions_policy_analysis = analyze_permissions_policy(headers.get("permissions-policy", ""), report_only=False)
    permissions_policy_report_only_analysis = analyze_permissions_policy(
        headers.get("permissions-policy-report-only", ""),
        report_only=True,
    )

    findings: List[Dict] = []

    for header in SECURITY_HEADERS:
        value = headers.get(header)
        status = "Present" if value else "Missing"
        severity = "Low"
        detail = ""

        if header == "content-security-policy":
            if not value:
                severity = "High"
                detail = "CSP not configured"
            elif "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower():
                severity = "Medium"
                detail = "CSP allows unsafe-inline/unsafe-eval"
            else:
                detail = "CSP present"

        elif header == "strict-transport-security":
            if is_https and not value:
                severity = "Medium"
                detail = "HSTS missing on HTTPS site"
            elif value:
                lower_value = value.lower()
                match = re.search(r"max-age=(\d+)", lower_value)
                max_age = int(match.group(1)) if match else 0
                if max_age < 31536000:
                    severity = "Medium"
                    detail = "Weak HSTS max-age (recommended >= 31536000)"
                elif "includesubdomains" not in lower_value:
                    severity = "Medium"
                    detail = "HSTS missing includeSubDomains"
                elif "preload" not in lower_value:
                    severity = "Low"
                    detail = "HSTS present without preload"
                else:
                    detail = "HSTS present"
            else:
                detail = "HSTS not applicable on non-HTTPS URL"

        elif header == "x-frame-options":
            if not value:
                severity = "Medium"
                detail = "Missing clickjacking protection"
            elif value.upper() not in {"DENY", "SAMEORIGIN"}:
                severity = "Medium"
                detail = "Unexpected X-Frame-Options value"
            else:
                detail = "X-Frame-Options present"

        elif header == "x-content-type-options":
            if not value:
                severity = "Medium"
                detail = "Missing MIME sniffing protection"
            elif value.lower() != "nosniff":
                severity = "Medium"
                detail = "X-Content-Type-Options should be 'nosniff'"
            else:
                detail = "MIME sniffing protection enabled"

        elif header == "referrer-policy":
            if not value:
                severity = "Low"
                detail = "Referrer-Policy missing"
            else:
                detail = "Referrer-Policy present"

        elif header == "permissions-policy":
            if not value and permissions_policy_report_only_analysis["present"]:
                severity = "Medium"
                detail = "Permissions-Policy enforcement missing; report-only policy present"
            elif not value:
                severity = "Low"
                detail = "Permissions-Policy missing"
            else:
                severity = permissions_policy_analysis["severity"]
                detail = permissions_policy_analysis["detail"]

        elif header == "permissions-policy-report-only":
            if not value:
                severity = "Low"
                detail = "Permissions-Policy-Report-Only not present"
            else:
                severity = permissions_policy_report_only_analysis["severity"]
                detail = permissions_policy_report_only_analysis["detail"]

        elif header == "x-xss-protection":
            if not value:
                severity = "Low"
                detail = "X-XSS-Protection not set"
            elif value.strip() == "0":
                severity = "Medium"
                detail = "X-XSS-Protection explicitly disabled"
            else:
                detail = "X-XSS-Protection present"

        elif header == "cross-origin-opener-policy":
            if not value:
                severity = "Low"
                detail = "COOP missing"
            elif value.strip().lower() not in {"same-origin", "same-origin-allow-popups"}:
                severity = "Medium"
                detail = "COOP value is weak"
            else:
                detail = "COOP present"

        elif header == "cross-origin-resource-policy":
            if not value:
                severity = "Low"
                detail = "CORP missing"
            elif value.strip().lower() not in {"same-origin", "same-site", "cross-origin"}:
                severity = "Medium"
                detail = "CORP value is unusual"
            else:
                detail = "CORP present"

        elif header == "cross-origin-embedder-policy":
            if not value:
                severity = "Low"
                detail = "COEP missing"
            elif value.strip().lower() != "require-corp":
                severity = "Medium"
                detail = "COEP not set to require-corp"
            else:
                detail = "COEP present"

        findings.append(
            {
                "header": header,
                "status": status,
                "severity": severity,
                "value": value or "",
                "detail": detail,
            }
        )

    issue_lines = [
        f"{item['header']}: {item['detail']}"
        for item in findings
        if item["severity"] in {"Medium", "High"}
    ]
    high_count = sum(1 for item in findings if item["severity"] == "High")
    medium_count = sum(1 for item in findings if item["severity"] == "Medium")
    score = max(0, 100 - high_count * 20 - medium_count * 10)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    overall = max_severity([item["severity"] for item in findings])

    return {
        "findings": findings,
        "issues": issue_lines,
        "overall": overall,
        "grade": grade,
        "score": score,
        "csp": csp_analysis,
        "permissions_policy": permissions_policy_analysis,
        "permissions_policy_report_only": permissions_policy_report_only_analysis,
    }


def check_sensitive_exposure(base_url: str, manager: RequestManager) -> Dict:
    findings: List[Dict] = []

    probe_paths = build_sensitive_probe_paths()
    probe_map = {urljoin(base_url, path): path for path in probe_paths}
    responses = manager.get_many(list(probe_map.keys()), timeout=8)

    for probe_url, path in probe_map.items():
        resp = responses.get(probe_url)
        if not resp:
            continue

        body_preview = resp.text[:2000] if "text" in resp.headers.get("content-type", "").lower() else ""
        lower_preview = body_preview.lower()

        if path == "/robots.txt" and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "Low",
                    "detail": "robots.txt is exposed (normally public, but review disallowed entries)",
                }
            )

        elif path.startswith("/.git/") and resp.status_code == 200 and (
            "refs/heads" in lower_preview
            or "repositoryformatversion" in lower_preview
            or "[core]" in lower_preview
        ):
            findings.append(
                {
                    "path": path,
                    "severity": "High",
                    "detail": "Exposed Git repository metadata",
                }
            )

        elif path.endswith((".bak", ".old", ".backup")) and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "High",
                    "detail": "Potential backup file is publicly accessible",
                }
            )

        elif path.endswith((".zip", ".tar", ".tar.gz", ".gz")) and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "Medium",
                    "detail": "Potential archive/backup artifact is publicly accessible",
                }
            )

        elif path in {"/debug.log", "/.env"} and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "High" if path == "/.env" else "Medium",
                    "detail": "Environment/debug artifact appears publicly accessible",
                }
            )

        elif path == "/.aws/credentials" and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "High",
                    "detail": "AWS credentials file appears publicly accessible",
                }
            )

        elif path == "/id_rsa" and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "High",
                    "detail": "Private SSH key material may be publicly accessible",
                }
            )

        elif path == "/.DS_Store" and resp.status_code == 200:
            findings.append(
                {
                    "path": path,
                    "severity": "Medium",
                    "detail": "macOS metadata file (.DS_Store) exposed; may leak internal file structure",
                }
            )

    root_resp = manager.get(base_url, timeout=8, allow_redirects=True)
    if root_resp and root_resp.status_code == 200 and "index of /" in root_resp.text.lower():
        findings.append(
            {
                "path": "/",
                "severity": "Medium",
                "detail": "Directory listing appears enabled (Index of /)",
            }
        )

    overall = max_severity([item["severity"] for item in findings]) if findings else "Low"
    return {
        "findings": findings,
        "overall": overall,
    }


def evaluate_security(response: requests.Response) -> Dict:
    final_url = response.url
    final_scheme = urlparse(final_url).scheme.lower()
    is_https = final_scheme == "https"

    header_audit = audit_security_headers(response)

    missing_headers = [
        item["header"]
        for item in header_audit["findings"]
        if item["status"] == "Missing"
    ]

    security_issues: List[str] = []
    if not is_https:
        security_issues.append("Website is not using HTTPS")
    security_issues.extend(header_audit["issues"])

    levels = [header_audit["overall"]]
    if not is_https:
        levels.append("High")
    if len(missing_headers) >= 4:
        levels.append("High")
    elif len(missing_headers) >= 2:
        levels.append("Medium")

    vulnerability_level = max_severity(levels)

    return {
        "final_url": final_url,
        "is_https": is_https,
        "missing_headers": missing_headers,
        "issues": security_issues,
        "vulnerability_level": vulnerability_level,
        "header_audit": header_audit,
    }


def evaluate_phishing_signals(final_url: str, html: str, is_https: bool, domain_intel: Dict | None = None) -> Dict:
    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""
    lowered_url = final_url.lower()

    score = 0
    reasons: List[str] = []

    try:
        ipaddress.ip_address(hostname)
        score += 3
        reasons.append("Domain is an IP address")
    except ValueError:
        pass

    if "xn--" in hostname:
        score += 3
        reasons.append("Punycode domain detected")
    if hostname.count(".") >= 3:
        score += 1
        reasons.append("Many subdomains")
    if hostname.count("-") >= 3:
        score += 1
        reasons.append("Many hyphens in domain")
    if "@" in final_url:
        score += 2
        reasons.append("'@' symbol in URL")
    if len(final_url) > 90:
        score += 1
        reasons.append("Very long URL")

    if any(keyword in lowered_url for keyword in SUSPICIOUS_URL_KEYWORDS):
        score += 2
        reasons.append("Suspicious keywords in URL")

    soup = BeautifulSoup(html, "html.parser")
    has_password_input = bool(
        soup.find("input", attrs={"type": lambda value: str(value).lower() == "password"})
    )
    if has_password_input and not is_https:
        score += 3
        reasons.append("Password input found on non-HTTPS page")

    visual_confusion = (domain_intel or {}).get("visual_confusion", {}) if domain_intel else {}
    if visual_confusion.get("is_brand_lookalike"):
        lookalike_text = str(
            visual_confusion.get("lookalike_assessment", "Visual brand lookalike detected")
        )
        score += 3
        reasons.append(lookalike_text)
    elif int(visual_confusion.get("score", 0) or 0) >= 7 and visual_confusion.get("looks_like_domain"):
        score += 2
        reasons.append(
            f"Visual similarity indicates possible impersonation of {visual_confusion.get('looks_like_domain')}"
        )

    screenshot_similarity = (domain_intel or {}).get("screenshot_similarity", {}) if domain_intel else {}
    screenshot_signal_level = str(screenshot_similarity.get("signal_level", "Low") or "Low")
    if screenshot_signal_level == "High":
        score += 5
        reasons.append(
            str(
                screenshot_similarity.get(
                    "detail",
                    "Extremely strong phishing signal: screenshot visual similarity to known brand",
                )
            )
        )
    elif screenshot_signal_level == "Medium":
        score += 3
        reasons.append(
            str(
                screenshot_similarity.get(
                    "detail",
                    "Elevated phishing signal from screenshot visual similarity",
                )
            )
        )

    caa_signal = (domain_intel or {}).get("caa_evaluation", {}) if domain_intel else {}
    caa_signal_level = str(caa_signal.get("signal_level", "Low") or "Low")
    caa_signal_detail = str(caa_signal.get("signal_detail", "") or "")
    if caa_signal_level == "High":
        score += 4
        reasons.append(caa_signal_detail or "CAA record missing (very strong phishing infrastructure signal)")
    elif caa_signal_level == "Medium":
        score += 2
        reasons.append(caa_signal_detail or "CAA authorization appears weak")

    if score >= 7:
        phishing_level = "High"
        phishing_status = "Likely Fake/Phishing"
    elif score >= 4:
        phishing_level = "Medium"
        phishing_status = "Suspicious"
    else:
        phishing_level = "Low"
        phishing_status = "No strong phishing indicators"

    return {
        "score": score,
        "level": phishing_level,
        "status": phishing_status,
        "reasons": reasons,
    }


def analyze_website(
    target_url: str,
    allow_insecure_ssl: bool = False,
    compare_with: str = "",
    weight_profile: str = "balanced",
) -> Dict:
    normalized_url = normalize_target_url(target_url)
    if not normalized_url:
        return {
            "target": target_url,
            "ok": False,
            "error": "No URL provided",
        }

    response, error = fetch_target(normalized_url, verify_ssl=True)
    ssl_fallback_used = False
    note = ""
    if error and "ssl error" in error.lower() and allow_insecure_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response, error = fetch_target(normalized_url, verify_ssl=False)
        if response is not None and error is None:
            ssl_fallback_used = True
            note = "SSL verification was bypassed due to certificate validation failure. Results may be less trustworthy."

    if error or response is None:
        return {
            "target": normalized_url,
            "ok": False,
            "error": error or "Unknown error",
        }

    manager = RequestManager(session=requests.Session())
    manager.cache[normalized_url] = response
    manager.cache[response.url] = response

    security = evaluate_security(response)
    domain_intel = analyze_domain_intelligence(security["final_url"])
    phishing = evaluate_phishing_signals(
        security["final_url"], response.text, security["is_https"], domain_intel
    )
    app_risk = evaluate_application_indicators(security["final_url"], response)
    active_probe = active_light_probe(security["final_url"], manager)
    sensitive_exposure = check_sensitive_exposure(security["final_url"], manager)
    robots_info = analyze_robots(security["final_url"], manager)
    tls_info = analyze_tls(security["final_url"])
    cookie_audit = audit_cookies(response, security["is_https"])
    form_audit = audit_forms(response.text, security["final_url"], security["is_https"], response)
    resource_audit = analyze_resources(response.text, security["final_url"], security["is_https"])
    redirect_chain = analyze_redirect_chain(response)
    reputation_lookup = simple_phishing_lookup(security["final_url"])

    security_extras = max_severity(
        [
            tls_info["severity"],
            cookie_audit["severity"],
            form_audit["severity"],
            resource_audit["severity"],
        ]
    )

    aspect_levels = [
        security["vulnerability_level"],
        security_extras,
        phishing["level"],
        app_risk["overall"],
        active_probe["overall"],
        sensitive_exposure["overall"],
        domain_intel["severity"],
        redirect_chain["severity"],
        reputation_lookup["severity"],
    ]
    high_count = sum(1 for level in aspect_levels if level == "High")
    medium_count = sum(1 for level in aspect_levels if level == "Medium")

    if high_count >= 2:
        overall_verdict = "High Risk"
        verdict_reason = f"{high_count} high-risk aspects detected (High={high_count}, Medium={medium_count})"
    elif high_count == 1 or medium_count >= 2 or (not security["is_https"] and medium_count >= 1):
        overall_verdict = "Caution"
        if high_count == 1:
            verdict_reason = f"1 high-risk aspect detected (High={high_count}, Medium={medium_count})"
        elif medium_count >= 2:
            verdict_reason = f"{medium_count} medium-risk aspects detected (High={high_count}, Medium={medium_count})"
        else:
            verdict_reason = f"Non-HTTPS combined with additional risk (High={high_count}, Medium={medium_count})"
    else:
        overall_verdict = "Safe"
        verdict_reason = f"No high-risk aspects detected (High={high_count}, Medium={medium_count})"

    result = {
        "target": normalized_url,
        "ok": True,
        "status_code": response.status_code,
        "security": security,
        "security_extras": security_extras,
        "phishing": phishing,
        "app_risk": app_risk,
        "active_probe": active_probe,
        "sensitive_exposure": sensitive_exposure,
        "robots": robots_info,
        "tls": tls_info,
        "cookies": cookie_audit,
        "forms": form_audit,
        "resources": resource_audit,
        "domain_intel": domain_intel,
        "redirect_chain": redirect_chain,
        "reputation_lookup": reputation_lookup,
        "ssl_fallback_used": ssl_fallback_used,
        "note": note,
        "overall_verdict": overall_verdict,
        "verdict_reason": verdict_reason,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    apply_false_positive_suppressors(result)
    result["weighted_model"] = weighted_overall_score(result, weight_profile=weight_profile)
    result["output_accuracy"] = estimate_output_accuracy(result)
    result["remediation"] = {
        "security": REMEDIATION_GUIDANCE.get(result["security"]["vulnerability_level"], REMEDIATION_GUIDANCE["Low"]),
        "phishing": REMEDIATION_GUIDANCE.get(result["phishing"]["level"], REMEDIATION_GUIDANCE["Low"]),
        "application": REMEDIATION_GUIDANCE.get(result["app_risk"]["overall"], REMEDIATION_GUIDANCE["Low"]),
        "active_probe": REMEDIATION_GUIDANCE.get(result["active_probe"]["overall"], REMEDIATION_GUIDANCE["Low"]),
        "exposure": REMEDIATION_GUIDANCE.get(result["sensitive_exposure"]["overall"], REMEDIATION_GUIDANCE["Low"]),
    }
    result["historical_diff"] = compute_diff_with_previous(result, compare_with)

    return result


def print_terminal_report(result: Dict):
    console.rule("[bold cyan]Website Safety Check (vNext + Rich)")
    console.print(f"[bold]Target:[/bold] {result.get('target', '')}")

    if not result.get("ok"):
        console.print(f"[bold red]Scan failed:[/bold red] {result.get('error', 'Unknown error')}")
        return

    if result.get("note"):
        console.print(f"[yellow]Note:[/yellow] {result['note']}")

    security = result["security"]
    security_extras = result["security_extras"]
    phishing = result["phishing"]
    app_risk = result["app_risk"]
    active_probe = result["active_probe"]
    exposure = result["sensitive_exposure"]
    tls_info = result["tls"]
    cookie_audit = result["cookies"]
    form_audit = result["forms"]
    resource_audit = result["resources"]
    robots_info = result["robots"]
    domain_intel = result["domain_intel"]
    redirect_chain = result["redirect_chain"]
    reputation_lookup = result["reputation_lookup"]
    weighted_model = result["weighted_model"]
    output_accuracy = result.get("output_accuracy", {})
    historical_diff = result["historical_diff"]

    secured_text = "Yes" if security["is_https"] else "No"

    overview = Table(box=box.SIMPLE_HEAVY, expand=True)
    overview.add_column("Check", style="bold cyan")
    overview.add_column("Result")
    overview.add_column("Severity", justify="right")
    overview.add_row("HTTP Status", str(result["status_code"]), "-")
    overview.add_row("Final URL", security["final_url"], "-")
    overview.add_row("Secured (HTTPS)", secured_text, f"[{severity_rich_style('Low' if security['is_https'] else 'High')}]{severity_label('Low' if security['is_https'] else 'High')}[/]")
    overview.add_row("Vulnerability Risk", "Header/CSP baseline", f"[{severity_rich_style(security['vulnerability_level'])}]{severity_label(security['vulnerability_level'])}[/]")
    overview.add_row("Fake/Phishing Risk", phishing["status"], f"[{severity_rich_style(phishing['level'])}]{severity_label(phishing['level'])}[/]")
    overview.add_row("Application Risk (Passive)", f"confidence {app_risk['confidence_score']}%", f"[{severity_rich_style(app_risk['overall'])}]{severity_label(app_risk['overall'])}[/]")
    overview.add_row("Active Light Probe", "Safe active checks", f"[{severity_rich_style(active_probe['overall'])}]{severity_label(active_probe['overall'])}[/]")
    overview.add_row("Sensitive Exposure", "Files/directories", f"[{severity_rich_style(exposure['overall'])}]{severity_label(exposure['overall'])}[/]")
    overview.add_row("Security Extras", "TLS/Cookies/Forms/Resources", f"[{severity_rich_style(security_extras)}]{severity_label(security_extras)}[/]")
    overview.add_row("Reputation Lookup", "Blocklist/feed check", f"[{severity_rich_style(reputation_lookup['severity'])}]{severity_label(reputation_lookup['severity'])}[/]")
    weighted_profile = weighted_model.get("profile_label", weighted_model.get("profile", "Balanced"))

    overview.add_row(
        "Weighted Score",
        f"{weighted_model['score']}/100 ({weighted_model['band']} - {weighted_model.get('risk_label', '')})",
        f"[{severity_rich_style(weighted_model['band'])}]{severity_label(weighted_model['band'])}[/]",
    )
    overview.add_row("Weighted Profile", weighted_profile, "-")
    console.print(Panel(overview, title="Overview", border_style="cyan"))

    verdict = result["overall_verdict"]
    verdict_style = "bold green" if verdict == "Safe" else "bold yellow" if verdict == "Caution" else "bold red"
    console.print(Panel(f"[{verdict_style}]Overall Verdict: {verdict}[/]\n[bold]Reason:[/bold] {result.get('verdict_reason', '')}", title="Decision", border_style="magenta"))

    top_risks = top_risks_summary(
        [
            ("Security", security["vulnerability_level"], "Header/CSP baseline"),
            ("Phishing", phishing["level"], phishing["status"]),
            ("Application", app_risk["overall"], "Passive indicators"),
            ("Active Probe", active_probe["overall"], "Safe active checks"),
            ("Sensitive Exposure", exposure["overall"], "Files/directories"),
            ("TLS", tls_info["severity"], tls_info["detail"]),
            ("Cookies", cookie_audit["severity"], "Cookie flag audit"),
            ("Forms", form_audit["severity"], "Password form checks"),
            ("Resources", resource_audit["severity"], "External/mixed content"),
            ("Reputation", reputation_lookup["severity"], "Simple phishing list lookup"),
        ]
    )
    console.print(Panel("\n".join(f"• {item}" for item in top_risks), title="Top Risks", border_style="red"))

    weighted_table = Table(box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    weighted_table.add_column("Component", style="cyan")
    weighted_table.add_column("Level")
    weighted_table.add_column("Weight")
    weighted_table.add_column("Impact", justify="right")
    for component_name, level in weighted_model.get("components", {}).items():
        weight_pct = round(float(weighted_model.get("weights", {}).get(component_name, 0.0)) * 100, 1)
        impact = float(weighted_model.get("contributions", {}).get(component_name, 0.0))
        weighted_table.add_row(
            component_name.replace("_", " ").title(),
            f"[{severity_rich_style(level)}]{severity_label(level)}[/]",
            f"{weight_pct}%",
            f"{impact:.1f}",
        )

    weighted_summary_lines = [
        f"Profile: {weighted_profile}",
        f"Focus: {weighted_model.get('profile_focus', '')}",
        f"Best for: {weighted_model.get('profile_best_for', '')}",
        f"Risk Index: {weighted_model['score']}/100 ({weighted_model['band']} - {weighted_model.get('risk_label', '')})",
        f"Risk pressure: {weighted_model.get('risk_pressure', 0)}% of model weight is currently Medium/High",
        f"Dominant component: {weighted_model.get('dominant_component', '').replace('_', ' ').title() or 'None'} ({weighted_model.get('dominant_impact', 0.0):.1f})",
        f"Signal distribution: High={weighted_model.get('high_count', 0)}, Medium={weighted_model.get('medium_count', 0)}",
        f"Outlook: {weighted_model.get('outlook', '')}",
    ]
    weighted_summary_lines.extend(
        weighted_model.get("top_drivers", []) or ["No high-impact weighted drivers"]
    )
    console.print(Panel("\n".join(weighted_summary_lines), title="Weighted Score Highlights", border_style="yellow"))
    console.print(weighted_table)

    console.print("[bold magenta]Security Headers Audit[/bold magenta]")
    header_table = Table(box=box.MINIMAL_DOUBLE_HEAD)
    header_table.add_column("Header", style="cyan")
    header_table.add_column("Status")
    header_table.add_column("Severity")
    header_table.add_column("Detail")
    for item in security["header_audit"]["findings"]:
        header_table.add_row(
            item["header"],
            item["status"],
            f"[{severity_rich_style(item['severity'])}]{severity_label(item['severity'])}[/]",
            item["detail"],
        )
    console.print(header_table)
    console.print(f"Header grade: [bold]{security['header_audit']['grade']}[/bold] ({security['header_audit']['score']}/100)")
    console.print(f"CSP analysis: {security['header_audit']['csp']['detail']}")
    pp_summary = security["header_audit"].get("permissions_policy", {})
    pp_ro_summary = security["header_audit"].get("permissions_policy_report_only", {})
    console.print(f"Permissions-Policy: {pp_summary.get('detail', '')}")
    console.print(f"Permissions-Policy-Report-Only: {pp_ro_summary.get('detail', '')}")

    console.print("\n[bold magenta]TLS / Certificate[/bold magenta]")
    if tls_info.get("supported"):
        console.print(f"- TLS Grade: {tls_info.get('tls_grade', 'N/A')} ({tls_info.get('tls_score', 0)}/100)")
        tls_conf = tls_info.get("tls_confidence", {})
        console.print(
            f"- TLS Confidence: {tls_conf.get('level', 'Low')} ({tls_conf.get('score', 0)}/100) - {tls_conf.get('summary', '')}"
        )
        console.print(f"- TLS Version: {tls_info.get('tls_version', '')}")
        console.print(f"- ALPN: {tls_info.get('alpn', '') or 'Not negotiated'}")
        console.print(f"- Cipher: {tls_info.get('cipher', '')} ({tls_info.get('cipher_bits', 0)} bits)")
        console.print(f"- Hostname match: {'Yes' if tls_info.get('hostname_match') else 'No'}")
        if tls_info.get("matched_patterns"):
            console.print(f"- Matched SAN/CN: {', '.join(tls_info.get('matched_patterns', [])[:3])}")
        console.print(f"- Self-signed: {'Yes' if tls_info.get('self_signed') else 'No'}")
        console.print(f"- SAN entries: {tls_info.get('san_count', 0)}")
        if tls_info.get("san_dns"):
            console.print(f"- SAN sample: {', '.join(tls_info.get('san_dns', [])[:3])}")
        console.print(f"- Issuer: {tls_info.get('issuer', '')}")
        console.print(f"- Subject: {tls_info.get('subject', '')}")
        console.print(f"- Expires: {tls_info.get('not_after', '')} ({tls_info.get('days_left', 'n/a')} days)")
        console.print(f"- Certificate age: {tls_info.get('cert_age_days', 'n/a')} days")
        for tls_finding in tls_info.get("findings", []):
            console.print(f"- TLS finding: {tls_finding}")
    console.print(f"- Status: {tls_info.get('detail', '')}")

    console.print("\n[bold magenta]Cookie Audit[/bold magenta]")
    cookie_summary = cookie_audit.get("summary", {})
    if cookie_summary:
        same_site_summary = cookie_summary.get("samesite", {})
        console.print(
            "- Cookie summary: "
            f"total={cookie_summary.get('total', 0)}, "
            f"Secure={cookie_summary.get('secure', 0)}, "
            f"HttpOnly={cookie_summary.get('httponly', 0)}, "
            f"SameSite(strict/lax/none/missing/other)="
            f"{same_site_summary.get('strict', 0)}/{same_site_summary.get('lax', 0)}/"
            f"{same_site_summary.get('none', 0)}/{same_site_summary.get('missing', 0)}/{same_site_summary.get('other', 0)}"
        )
        console.print(
            "- Prefix compliance: "
            f"__Secure- {cookie_summary.get('secure_prefix_compliant', 0)}/{cookie_summary.get('secure_prefix_total', 0)}, "
            f"__Host- {cookie_summary.get('host_prefix_compliant', 0)}/{cookie_summary.get('host_prefix_total', 0)}"
        )
    if cookie_audit["issues"]:
        for issue in cookie_audit["issues"]:
            console.print(f"- {issue}")
    else:
        console.print("- No cookie issues detected")

    console.print("\n[bold magenta]Form Security Audit[/bold magenta]")
    if form_audit["findings"]:
        for item in form_audit["findings"]:
            console.print(f"- {item}")
    else:
        console.print("- No password form issues detected")

    console.print("\n[bold magenta]Resource Integrity[/bold magenta]")
    if resource_audit["mixed_content"]:
        console.print(f"- Mixed content URLs: {len(resource_audit['mixed_content'])}")
    if resource_audit["missing_sri"]:
        console.print(f"- External scripts missing SRI: {len(resource_audit['missing_sri'])}")
    console.print(f"- External JS: {len(resource_audit['external_js'])}, CSS: {len(resource_audit['external_css'])}")

    console.print("\n[bold magenta]Robots.txt Intelligence[/bold magenta]")
    if robots_info["found"]:
        console.print(f"- Disallowed paths: {len(robots_info['disallowed'])}")
        if robots_info["sensitive"]:
            console.print(f"- Sensitive disallows: {', '.join(robots_info['sensitive'])}")
    else:
        console.print("- robots.txt not found")

    console.print("\n[bold magenta]Domain Intelligence[/bold magenta]")
    console.print(f"- Host: {domain_intel['hostname']}")
    console.print(f"- Severity: [bold]{domain_intel['severity']}[/bold]")
    confusion_view = domain_intel.get("visual_confusion", {})
    console.print(
        f"- Visual confusion score: {confusion_view.get('score', 0)}/10"
        + (
            f" (matched label: {confusion_view.get('matched_label', '')}, closest brand: {confusion_view.get('closest_brand', '')}, distance={confusion_view.get('distance')}, similarity={confusion_view.get('similarity', 0.0)})"
            if confusion_view.get("closest_brand")
            else ""
        )
    )
    if confusion_view.get("lookalike_assessment"):
        console.print(
            f"- Lookalike hint: {confusion_view.get('lookalike_assessment', '')}"
        )
    screenshot_view = domain_intel.get("screenshot_similarity", {})
    console.print(
        f"- Screenshot visual signal: {screenshot_view.get('signal_level', 'Low')}"
        f" ({screenshot_view.get('detail', '')})"
    )
    if screenshot_view.get("brand_domain"):
        console.print(
            f"- Screenshot reference brand: {screenshot_view.get('brand_domain')} | "
            f"similarity={screenshot_view.get('similarity_pct', 0)}% | "
            f"distance={screenshot_view.get('hamming_distance')}")
    if confusion_view.get("decoded_hostname") and confusion_view.get("decoded_hostname") != domain_intel.get("hostname", ""):
        console.print(f"- Decoded punycode hostname: {confusion_view.get('decoded_hostname')}")
    console.print(
        f" - SPF: {'Present' if domain_intel.get('email_auth', {}).get('spf_present') else 'Missing'}, "
        f"DMARC: {'Present' if domain_intel.get('email_auth', {}).get('dmarc_present') else 'Missing'}"
    )
    dmarc_view = domain_intel.get("email_auth", {}).get("dmarc_analysis", {})
    if domain_intel.get("email_auth", {}).get("dmarc_present"):
        console.print(
            f" - DMARC policy: {dmarc_view.get('policy', '') or 'unknown'}; "
            f"pct={dmarc_view.get('pct', 100)}; "
            f"rua={'configured' if dmarc_view.get('rua') else 'not set'}"
        )
        console.print(f" - DMARC effective policy: {dmarc_view.get('effective_policy', '')}")
    console.print(f" - CAA: {'Present' if domain_intel.get('caa_present') else 'Missing'}")
    console.print(
        f" - CAA phishing signal: {domain_intel.get('caa_evaluation', {}).get('signal_level', 'Low')}"
        f" ({domain_intel.get('caa_evaluation', {}).get('signal_detail', '')})"
    )
    if domain_intel.get("caa_records"):
        console.print(f" - CAA records: {', '.join(domain_intel.get('caa_records', [])[:3])}")
        console.print(
            f" - CAA issue auth: {'Yes' if domain_intel.get('caa_evaluation', {}).get('has_issue_authorization') else 'No'}, "
            f"iodef: {'Yes' if domain_intel.get('caa_evaluation', {}).get('has_iodef') else 'No'}"
        )
    if domain_intel.get("homoglyph", {}).get("homoglyph_detected"):
        console.print(f"- Homoglyph warning: {domain_intel.get('homoglyph', {}).get('normalized_hint', '')}")
    if domain_intel["whois"].get("creation_date"):
        console.print(f"- Created: {domain_intel['whois']['creation_date']} ({domain_intel['whois'].get('days_old')} days old)")
    if domain_intel["findings"]:
        for item in domain_intel["findings"]:
            console.print(f"- {item}")

    if redirect_chain["hops"]:
        console.print(f"\n[bold magenta]Redirect Chain ({severity_label(redirect_chain['severity'])})[/bold magenta]")
        for hop in redirect_chain["hops"]:
            console.print(f"- {hop['status']} {hop['from']} -> {hop['to']}")
        for finding in redirect_chain.get("findings", []):
            console.print(f"- Redirect finding: {finding}")

    console.print("\n[bold magenta]Simple Reputation Lookup[/bold magenta]")
    console.print(f"- Listed: {'Yes' if reputation_lookup.get('listed') else 'No'}")
    console.print(f"- Primary source: {reputation_lookup.get('primary_source', 'none')}")
    console.print(f"- Google Safe Browsing: {reputation_lookup.get('google_safe_browsing_status', 'not_checked')}")
    if reputation_lookup.get("google_safe_browsing_threat_types"):
        console.print(f"- Google threat types: {', '.join(reputation_lookup.get('google_safe_browsing_threat_types', []))}")
    console.print(f"- URLhaus status: {reputation_lookup.get('urlhaus_status', '')}")
    if reputation_lookup.get("findings"):
        for item in reputation_lookup["findings"]:
            console.print(f"- {item}")

    console.print("\n[bold magenta]Remediation Guidance[/bold magenta]")
    for key, text in result["remediation"].items():
        console.print(f"- {key}: {text}")

    if historical_diff.get("enabled"):
        console.print("\n[bold magenta]Historical Diff[/bold magenta]")
        for change in historical_diff.get("changes", []):
            console.print(f"- {change}")

    if security["issues"]:
        console.print("\n[bold magenta]Security Findings[/bold magenta]")
        for issue in security["issues"]:
            console.print(f"- {issue}")

    console.print("\n[bold magenta]Application Passive Indicators[/bold magenta]")
    app_table = Table(box=box.SIMPLE)
    app_table.add_column("Category", style="cyan")
    app_table.add_column("Severity")
    app_table.add_column("Detail")
    for item in app_risk["findings"]:
        app_table.add_row(
            item["category"],
            f"[{severity_rich_style(item['severity'])}]{severity_label(item['severity'])}[/]",
            item["detail"],
        )
    console.print(app_table)

    console.print("\n[bold magenta]Active Light Probing Indicators[/bold magenta]")
    active_table = Table(box=box.SIMPLE)
    active_table.add_column("Check", style="cyan")
    active_table.add_column("Severity")
    active_table.add_column("Detail")
    for item in active_probe["findings"]:
        active_table.add_row(
            item["check"],
            f"[{severity_rich_style(item['severity'])}]{severity_label(item['severity'])}[/]",
            item["detail"],
        )
    console.print(active_table)

    if phishing["reasons"]:
        console.print("\n[bold magenta]Phishing Indicators[/bold magenta]")
        for reason in phishing["reasons"]:
            console.print(f"- {reason}")

    if exposure["findings"]:
        console.print("\n[bold magenta]Sensitive Exposure Findings[/bold magenta]")
        for item in exposure["findings"]:
            console.print(f"- {item['path']} [{item['severity']}]: {item['detail']}")

    if not security["issues"] and not phishing["reasons"] and not exposure["findings"] and app_risk["overall"] == "Low":
        console.print("[bold green]No major red flags were detected by current checks.[/bold green]")

    accuracy_lines = [
        f"Output Accuracy: {output_accuracy.get('percentage', 0)}% ({output_accuracy.get('level', 'Low')})",
        f"Summary: {output_accuracy.get('summary', '')}",
        (
            "Inputs: "
            f"app={output_accuracy.get('inputs', {}).get('app_confidence', 0)}%, "
            f"tls={output_accuracy.get('inputs', {}).get('tls_confidence', 0)}%, "
            f"coverage={output_accuracy.get('inputs', {}).get('check_coverage', 0)}%, "
            f"transport={output_accuracy.get('inputs', {}).get('transport_reliability', 0)}%, "
            f"execution={output_accuracy.get('inputs', {}).get('execution_health', 0)}%"
        ),
    ]
    adjustments = output_accuracy.get("adjustments", [])
    if adjustments:
        accuracy_lines.append(f"Adjustments: {', '.join(adjustments)}")
    console.print(Panel("\n".join(accuracy_lines), title="Output Accuracy (Final)", border_style="bright_blue"))

# ─── Report ──────────────────────────────────────────────────────────────────


def generate_report(result: Dict, output_file: str = "site_report.md"):
    checked_at = str(result.get("checked_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    if not result.get("ok"):
        markdown = (
            "# Website Safety Report\n\n"
            f"- Generated: {checked_at}\n"
            f"- Status: Failed\n"
            f"- Error: {result.get('error', 'Unknown error')}\n"
        )
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(markdown)
        console.print(f"\n[bold green]Markdown report saved →[/bold green] {output_file}")
        return

    security = result.get("security", {})
    phishing = result.get("phishing", {})
    app_risk = result.get("app_risk", {})
    active_probe = result.get("active_probe", {})
    exposure = result.get("sensitive_exposure", {})
    tls_info = result.get("tls", {})
    domain_intel = result.get("domain_intel", {})
    redirect_chain = result.get("redirect_chain", {})
    reputation = result.get("reputation_lookup", {})
    weighted = result.get("weighted_model", {})
    output_accuracy = result.get("output_accuracy", {})
    remediation = result.get("remediation", {})
    historical_diff = result.get("historical_diff", {})

    top_risks = top_risks_summary(
        [
            ("Security", str(security.get("vulnerability_level", "Low")), "Header/CSP baseline"),
            ("Phishing", str(phishing.get("level", "Low")), str(phishing.get("status", ""))),
            ("Application", str(app_risk.get("overall", "Low")), "Passive indicators"),
            ("Active Probe", str(active_probe.get("overall", "Low")), "Safe active checks"),
            ("Sensitive Exposure", str(exposure.get("overall", "Low")), "Files/directories"),
        ]
    )

    lines: List[str] = []
    lines.append("# Website Safety Report")
    lines.append("")
    lines.append(f"- Generated: {checked_at}")
    lines.append(f"- Target: {result.get('target', '')}")
    lines.append(f"- Checked URL: {security.get('final_url', '')}")
    lines.append(f"- Verdict: {result.get('overall_verdict', '')}")
    lines.append(f"- Reason: {result.get('verdict_reason', '')}")
    if result.get("note"):
        lines.append(f"- Note: {result.get('note')}")
    lines.append("")

    lines.append("## Weighted Score")
    lines.append(f"- Score: {weighted.get('score', 0)}/100")
    lines.append(f"- Band: {weighted.get('band', 'Low')} ({weighted.get('risk_label', '')})")
    lines.append(f"- Profile: {weighted.get('profile_label', weighted.get('profile', 'Balanced'))}")
    lines.append(f"- Risk Pressure: {weighted.get('risk_pressure', 0)}%")
    lines.append(f"- Outlook: {weighted.get('outlook', '')}")
    lines.append("")

    lines.append("## Top Risks")
    if top_risks:
        lines.extend([f"- {item}" for item in top_risks])
    else:
        lines.append("- No major risks detected")
    lines.append("")

    lines.append("## Risk Levels")
    lines.append(f"- Security: {security.get('vulnerability_level', 'Low')}")
    lines.append(f"- Phishing: {phishing.get('level', 'Low')}")
    lines.append(f"- Application: {app_risk.get('overall', 'Low')}")
    lines.append(f"- Active Probe: {active_probe.get('overall', 'Low')}")
    lines.append(f"- Sensitive Exposure: {exposure.get('overall', 'Low')}")
    lines.append(f"- Domain Intelligence: {domain_intel.get('severity', 'Low')}")
    lines.append(f"- Redirect Chain: {redirect_chain.get('severity', 'Low')}")
    lines.append(f"- Reputation: {reputation.get('severity', 'Low')}")
    lines.append("")

    lines.append("## Security Findings")
    issues = [str(item) for item in security.get("issues", [])]
    lines.extend([f"- {item}" for item in issues] if issues else ["- No major security issues detected"])
    lines.append("")

    lines.append("## Phishing Indicators")
    reasons = [str(item) for item in phishing.get("reasons", [])]
    lines.extend([f"- {item}" for item in reasons] if reasons else ["- No strong phishing indicators detected"])
    lines.append("")

    lines.append("## Exposure Findings")
    exposure_findings = [f"{item['path']} [{item['severity']}]: {item['detail']}" for item in exposure.get("findings", [])]
    lines.extend([f"- {item}" for item in exposure_findings] if exposure_findings else ["- No sensitive exposure findings"])
    lines.append("")

    lines.append("## TLS")
    lines.append(f"- Status: {tls_info.get('detail', '')}")
    lines.append(f"- Grade: {tls_info.get('tls_grade', 'N/A')} ({tls_info.get('tls_score', 0)}/100)")
    lines.append(f"- Version: {tls_info.get('tls_version', '')}")
    lines.append(f"- Cipher: {tls_info.get('cipher', '')} ({tls_info.get('cipher_bits', 0)} bits)")
    lines.append(f"- Issuer: {tls_info.get('issuer', '')}")
    tls_findings = [str(item) for item in tls_info.get("findings", [])]
    lines.extend([f"- {item}" for item in tls_findings] if tls_findings else ["- No TLS findings"])
    lines.append("")

    lines.append("## Domain Intelligence")
    lines.append(f"- Host: {domain_intel.get('hostname', '')}")
    lines.append(f"- Visual Confusion Score: {domain_intel.get('visual_confusion', {}).get('score', 0)}/10")
    lines.append(f"- Closest Brand: {domain_intel.get('visual_confusion', {}).get('closest_brand', '')}")
    lines.append(f"- Screenshot Signal: {domain_intel.get('screenshot_similarity', {}).get('signal_level', 'Low')}")
    domain_findings = [str(item) for item in domain_intel.get("findings", [])]
    lines.extend([f"- {item}" for item in domain_findings] if domain_findings else ["- No domain findings"])
    lines.append("")

    lines.append("## Remediation Guidance")
    if remediation:
        for key, value in remediation.items():
            lines.append(f"- {str(key).capitalize()}: {value}")
    else:
        lines.append("- No remediation guidance generated")
    lines.append("")

    lines.append("## Historical Diff")
    changes = [str(item) for item in historical_diff.get("changes", [])] if historical_diff.get("enabled") else []
    lines.extend([f"- {item}" for item in changes] if changes else ["- Historical diff not enabled for this scan."])
    lines.append("")

    lines.append("## Output Accuracy (Final)")
    lines.append(f"- Accuracy: {output_accuracy.get('percentage', 0)}% ({output_accuracy.get('level', 'Low')})")
    lines.append(f"- Summary: {output_accuracy.get('summary', '')}")
    lines.append(
        "- Inputs: "
        f"app={output_accuracy.get('inputs', {}).get('app_confidence', 0)}%, "
        f"tls={output_accuracy.get('inputs', {}).get('tls_confidence', 0)}%, "
        f"coverage={output_accuracy.get('inputs', {}).get('check_coverage', 0)}%, "
        f"transport={output_accuracy.get('inputs', {}).get('transport_reliability', 0)}%, "
        f"execution={output_accuracy.get('inputs', {}).get('execution_health', 0)}%"
    )
    output_adjustments = output_accuracy.get("adjustments", [])
    lines.append(
        f"- Adjustments: {', '.join(output_adjustments)}"
        if output_adjustments
        else "- Adjustments: none"
    )

    markdown = "\n".join(lines).rstrip() + "\n"
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(markdown)
    console.print(f"\n[bold green]Markdown report saved →[/bold green] {output_file}")


def normalize_verdict_label(value: str) -> str:
    text = (value or "").strip().lower()
    if text in {"high", "high risk", "malicious", "dangerous"}:
        return "High Risk"
    if text in {"medium", "moderate", "caution", "suspicious", "guarded"}:
        return "Caution"
    if text in {"low", "safe", "benign", "stable"}:
        return "Safe"
    return ""


def evaluate_true_accuracy_benchmark(
    benchmark_file: str,
    allow_insecure_ssl: bool = False,
    weight_profile: str = "balanced",
) -> Dict:
    confusion: Dict[str, Dict[str, int]] = {
        label: {predicted: 0 for predicted in VERDICT_CLASSES}
        for label in VERDICT_CLASSES
    }
    invalid_rows: List[str] = []
    scan_failures: List[str] = []
    sample_predictions: List[Dict[str, str]] = []

    total_rows = 0
    evaluated = 0
    correct = 0

    with open(benchmark_file, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            raise ValueError("Benchmark CSV has no header row")

        for row_number, row in enumerate(reader, start=2):
            total_rows += 1
            url = (row.get("url") or row.get("target") or "").strip()
            expected_raw = (row.get("label") or row.get("ground_truth") or row.get("expected") or "").strip()
            expected_label = normalize_verdict_label(expected_raw)

            if not url or not expected_label:
                invalid_rows.append(
                    f"line {row_number}: missing/invalid url or label (label must map to Safe/Caution/High Risk)"
                )
                continue

            scan = analyze_website(
                url,
                allow_insecure_ssl=allow_insecure_ssl,
                compare_with="",
                weight_profile=weight_profile,
            )
            if not scan.get("ok"):
                scan_failures.append(f"{url} -> {scan.get('error', 'scan failed')}")
                continue

            predicted_label = normalize_verdict_label(str(scan.get("overall_verdict", ""))) or "Caution"
            confusion[expected_label][predicted_label] += 1
            evaluated += 1
            if predicted_label == expected_label:
                correct += 1

            if len(sample_predictions) < 10:
                sample_predictions.append(
                    {
                        "url": url,
                        "expected": expected_label,
                        "predicted": predicted_label,
                        "verdict": str(scan.get("overall_verdict", "")),
                    }
                )

    per_class: Dict[str, Dict[str, float]] = {}
    present_labels: List[str] = []
    for label in VERDICT_CLASSES:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in VERDICT_CLASSES if other != label)
        fn = sum(confusion[label][other] for other in VERDICT_CLASSES if other != label)
        support = sum(confusion[label][predicted] for predicted in VERDICT_CLASSES)
        if support > 0:
            present_labels.append(label)

        precision = (tp / (tp + fp) * 100) if (tp + fp) else 0.0
        recall = (tp / (tp + fn) * 100) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        per_class[label] = {
            "precision": round(precision, 1),
            "recall": round(recall, 1),
            "f1": round(f1, 1),
            "support": support,
        }

    metric_labels = present_labels or VERDICT_CLASSES
    macro_precision = round(sum(per_class[label]["precision"] for label in metric_labels) / len(metric_labels), 1)
    macro_recall = round(sum(per_class[label]["recall"] for label in metric_labels) / len(metric_labels), 1)
    macro_f1 = round(sum(per_class[label]["f1"] for label in metric_labels) / len(metric_labels), 1)
    true_accuracy = round((correct / evaluated) * 100, 1) if evaluated else 0.0

    return {
        "benchmark_file": benchmark_file,
        "total_rows": total_rows,
        "evaluated": evaluated,
        "correct": correct,
        "invalid_rows": invalid_rows,
        "scan_failures": scan_failures,
        "true_accuracy": true_accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "per_class": per_class,
        "confusion": confusion,
        "sample_predictions": sample_predictions,
    }


def print_true_accuracy_report(benchmark: Dict):
    console.rule("[bold cyan]True Accuracy Benchmark")
    summary = Table(box=box.SIMPLE_HEAVY, expand=True)
    summary.add_column("Metric", style="bold cyan")
    summary.add_column("Value")
    summary.add_row("Benchmark File", str(benchmark.get("benchmark_file", "")))
    summary.add_row("Rows in File", str(benchmark.get("total_rows", 0)))
    summary.add_row("Evaluated", str(benchmark.get("evaluated", 0)))
    summary.add_row("Correct", str(benchmark.get("correct", 0)))
    summary.add_row("True Accuracy", f"{benchmark.get('true_accuracy', 0)}%")
    summary.add_row("Macro Precision", f"{benchmark.get('macro_precision', 0)}%")
    summary.add_row("Macro Recall", f"{benchmark.get('macro_recall', 0)}%")
    summary.add_row("Macro F1", f"{benchmark.get('macro_f1', 0)}%")
    console.print(Panel(summary, title="Benchmark Summary", border_style="bright_blue"))

    class_table = Table(box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    class_table.add_column("Class", style="cyan")
    class_table.add_column("Support", justify="right")
    class_table.add_column("Precision", justify="right")
    class_table.add_column("Recall", justify="right")
    class_table.add_column("F1", justify="right")
    for label in VERDICT_CLASSES:
        metrics = benchmark.get("per_class", {}).get(label, {})
        class_table.add_row(
            label,
            str(metrics.get('support', 0)),
            f"{metrics.get('precision', 0)}%",
            f"{metrics.get('recall', 0)}%",
            f"{metrics.get('f1', 0)}%",
        )
    console.print(Panel(class_table, title="Per-Class Metrics", border_style="cyan"))

    confusion_table = Table(box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    confusion_table.add_column("Expected \\ Pred", style="cyan")
    for label in VERDICT_CLASSES:
        confusion_table.add_column(label, justify="right")
    for expected in VERDICT_CLASSES:
        row = [expected]
        for predicted in VERDICT_CLASSES:
            row.append(str(benchmark.get("confusion", {}).get(expected, {}).get(predicted, 0)))
        confusion_table.add_row(*row)
    console.print(Panel(confusion_table, title="Confusion Matrix", border_style="magenta"))

    invalid_rows = benchmark.get("invalid_rows", [])
    scan_failures = benchmark.get("scan_failures", [])
    if invalid_rows:
        console.print("[yellow]Skipped rows:[/yellow]")
        for item in invalid_rows[:10]:
            console.print(f"- {item}")
    if scan_failures:
        console.print("[yellow]Scan failures:[/yellow]")
        for item in scan_failures[:10]:
            console.print(f"- {item}")


def generate_true_accuracy_report(benchmark: Dict, output_file: str = "site_report.md"):
    lines: List[str] = []
    lines.append("# True Accuracy Benchmark Report")
    lines.append("")
    lines.append(f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- Benchmark File: {benchmark.get('benchmark_file', '')}")
    lines.append(f"- Rows in File: {benchmark.get('total_rows', 0)}")
    lines.append(f"- Evaluated: {benchmark.get('evaluated', 0)}")
    lines.append(f"- Correct: {benchmark.get('correct', 0)}")
    lines.append("")

    lines.append("## Core Metrics")
    lines.append(f"- True Accuracy: {benchmark.get('true_accuracy', 0)}%")
    lines.append(f"- Macro Precision: {benchmark.get('macro_precision', 0)}%")
    lines.append(f"- Macro Recall: {benchmark.get('macro_recall', 0)}%")
    lines.append(f"- Macro F1: {benchmark.get('macro_f1', 0)}%")
    lines.append("")

    lines.append("## Per-Class Metrics")
    for label in VERDICT_CLASSES:
        metrics = benchmark.get("per_class", {}).get(label, {})
        lines.append(
            f"- {label}: support={metrics.get('support', 0)}, precision={metrics.get('precision', 0)}%, recall={metrics.get('recall', 0)}%, f1={metrics.get('f1', 0)}%"
        )
    lines.append("")

    lines.append("## Confusion Matrix")
    lines.append("- Expected\\Pred: Safe | Caution | High Risk")
    for expected in VERDICT_CLASSES:
        row_values = [
            str(benchmark.get("confusion", {}).get(expected, {}).get(predicted, 0))
            for predicted in VERDICT_CLASSES
        ]
        lines.append(f"- {expected}: {' | '.join(row_values)}")
    lines.append("")

    invalid_rows = benchmark.get("invalid_rows", [])
    lines.append("## Skipped Rows")
    lines.extend([f"- {item}" for item in invalid_rows] if invalid_rows else ["- None"])
    lines.append("")

    scan_failures = benchmark.get("scan_failures", [])
    lines.append("## Scan Failures")
    lines.extend([f"- {item}" for item in scan_failures] if scan_failures else ["- None"])

    markdown = "\n".join(lines).rstrip() + "\n"
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(markdown)
    console.print(f"\n[bold green]Markdown report saved →[/bold green] {output_file}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Website Safety Checker (Rich terminal + Markdown report)"
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=cli_version_text(),
        help="Show tool version and exit",
    )
    parser.add_argument("url", nargs="?", help="Website URL to check")
    parser.add_argument(
        "--markdown-output",
        "--md-output",
        default="site_report.md",
        dest="markdown_output",
        help="Primary Markdown report file",
    )
    parser.add_argument("--output", dest="markdown_output", help="Alias for --markdown-output")
    parser.add_argument(
        "--weight-profile",
        choices=["balanced", "strict", "phishing-focused"],
        default="balanced",
        help="Weighted score profile (balanced, strict, phishing-focused)",
    )
    parser.add_argument("--compare-with", default="", help="Previous Markdown report path for diffing")
    parser.add_argument(
        "--allow-insecure-ssl",
        action="store_true",
        help="Retry without SSL certificate verification if SSL validation fails",
    )
    parser.add_argument(
        "--benchmark-file",
        default="",
        help="CSV file with labeled URLs to compute true accuracy (columns: url,label)",
    )
    args = parser.parse_args()

    compare_source = args.compare_with if args.compare_with else (args.markdown_output if os.path.exists(args.markdown_output) else "")

    if args.benchmark_file:
        try:
            benchmark = evaluate_true_accuracy_benchmark(
                args.benchmark_file,
                allow_insecure_ssl=args.allow_insecure_ssl,
                weight_profile=args.weight_profile,
            )
        except Exception as exc:
            parser.error(f"Benchmark failed: {exc}")
            return

        print_true_accuracy_report(benchmark)
        generate_true_accuracy_report(benchmark, args.markdown_output)
        return

    target = args.url
    if not target:
        try:
            target = input("Enter website URL to check: ").strip()
        except EOFError:
            parser.error("No URL input available. Use --url when running non-interactively.")

    if not target:
        parser.error("URL is required. Enter one at prompt or pass --url.")

    console.print(f"\n[bold yellow]Checking website:[/bold yellow] {target}")
    console.print("[yellow]This tool uses heuristics. Always verify with trusted sources.[/yellow]\n")

    result = analyze_website(
        target,
        allow_insecure_ssl=args.allow_insecure_ssl,
        compare_with=compare_source,
        weight_profile=args.weight_profile,
    )
    print_terminal_report(result)
    generate_report(result, args.markdown_output)

if __name__ == "__main__":
    main()