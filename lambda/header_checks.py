"""Pure, network-free logic for the SecHeaders agent.

Everything here is plain functions on plain data (dicts / lists / strings) so it
can be unit-tested offline AND reused unchanged from both the local tool and the
AWS Lambda function. No `requests`, no `strands`, no AWS imports.
"""
from __future__ import annotations

from typing import Any

# Security headers we grade, with severity, why they matter, and the fix.
SECURITY_HEADERS: dict[str, dict[str, str]] = {
    "Strict-Transport-Security": {
        "severity": "High",
        "why": "Forces browsers to use HTTPS, blocking protocol-downgrade and cookie-hijack attacks.",
        "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "why": "The strongest defence against cross-site scripting (XSS) and data injection.",
        "fix": "Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "why": "Stops your pages being embedded in a frame on another site (clickjacking).",
        "fix": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "why": "Stops browsers MIME-sniffing a response away from its declared content type.",
        "fix": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "why": "Controls how much referrer information leaks to other sites.",
        "fix": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "why": "Restricts which browser features (camera, mic, geolocation) the page may use.",
        "fix": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

# How many points each problem costs, starting from 100.
_SEVERITY_PENALTY = {"High": 25, "Medium": 15, "Low": 5}
_COOKIE_PENALTY = 8          # per insecure cookie (capped)
_COOKIE_PENALTY_CAP = 24
_NO_HTTPS_REDIRECT_PENALTY = 15


def analyze_headers(headers: dict[str, str]) -> tuple[list[str], list[dict[str, str]]]:
    """Split the checked security headers into present and missing.

    `headers` should be a case-insensitive-ish mapping of header name -> value.
    Returns (present_lines, missing) where each missing item is a dict with
    name, severity, why, fix.
    """
    # Build a lowercase index so lookups are case-insensitive.
    lower = {k.lower(): v for k, v in headers.items()}
    present: list[str] = []
    missing: list[dict[str, str]] = []
    for name, meta in SECURITY_HEADERS.items():
        if name.lower() in lower:
            present.append(f"{name}: {lower[name.lower()]}")
        else:
            missing.append({"name": name, **meta})
    return present, missing


def analyze_cookies(cookies: list[dict[str, Any]]) -> list[str]:
    """Return a list of human-readable cookie security issues.

    Each cookie dict should have: name (str), secure (bool), httponly (bool),
    samesite (str|None).
    """
    issues: list[str] = []
    for c in cookies:
        name = c.get("name", "<cookie>")
        flaws = []
        if not c.get("secure"):
            flaws.append("no Secure flag")
        if not c.get("httponly"):
            flaws.append("no HttpOnly flag")
        if not c.get("samesite"):
            flaws.append("no SameSite attribute")
        if flaws:
            issues.append(f"Cookie '{name}': " + ", ".join(flaws))
    return issues


def compute_grade(
    missing: list[dict[str, str]],
    cookie_issues: list[str],
    https_redirect: bool | None,
) -> tuple[str, int]:
    """Return (letter_grade, score 0-100) from the findings."""
    score = 100
    for m in missing:
        score -= _SEVERITY_PENALTY.get(m.get("severity", "Low"), 5)
    score -= min(len(cookie_issues) * _COOKIE_PENALTY, _COOKIE_PENALTY_CAP)
    if https_redirect is False:
        score -= _NO_HTTPS_REDIRECT_PENALTY
    score = max(0, min(100, score))

    if score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 60:
        letter = "D"
    else:
        letter = "F"
    return letter, score


def format_report(
    final_url: str,
    status_code: int,
    present: list[str],
    missing: list[dict[str, str]],
    cookie_issues: list[str],
    https_redirect: bool | None,
) -> str:
    """Build the full human-readable report the agent will read back."""
    letter, score = compute_grade(missing, cookie_issues, https_redirect)
    total = len(SECURITY_HEADERS)

    lines = [
        f"Security scan for {final_url} (HTTP {status_code})",
        f"GRADE: {letter}  ({score}/100)",
        "",
        f"Security headers present ({len(present)}/{total}):",
    ]
    lines += [f"  [OK]  {p}" for p in present] or ["  (none)"]
    lines.append("")

    if missing:
        lines.append(f"Security headers missing ({len(missing)}):")
        for m in missing:
            lines.append(f"  [MISSING - {m['severity']}] {m['name']}")
            lines.append(f"      Why: {m['why']}")
            lines.append(f"      Fix: add header ->  {m['fix']}")
    else:
        lines.append("All checked security headers are present. Excellent.")
    lines.append("")

    lines.append("HTTPS redirect:")
    if https_redirect is True:
        lines.append("  [OK]  http:// requests are redirected to https://")
    elif https_redirect is False:
        lines.append("  [WARN] http:// is NOT redirected to https:// (enable a redirect).")
    else:
        lines.append("  [n/a]  could not determine.")
    lines.append("")

    lines.append("Cookie security:")
    if cookie_issues:
        lines += [f"  [WARN] {i}" for i in cookie_issues]
    else:
        lines.append("  [OK]  no insecure cookies found (or no cookies set).")

    return "\n".join(lines)
