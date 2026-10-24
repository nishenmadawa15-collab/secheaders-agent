"""AWS Lambda handler for the SecHeaders scan.

This is a self-contained, dependency-free Lambda: it performs the HTTP fetch
using ONLY the Python standard library (urllib), so the deployment package needs
nothing beyond this file and its sibling `header_checks.py`. No `requests`, no
`strands`, no boto3.

Handler:  lambda_function.lambda_handler

It accepts either a direct-invoke payload  {"url": "example.com"}  or an API
Gateway proxy event (url in the JSON body or the query string), scans the target,
and returns {"grade", "score", "report", "url"} (or {"error": "..."}).

Run it locally without any AWS access:
    python lambda_function.py github.com
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import header_checks

_UA = "SecHeaders-Agent/2.0 (+non-intrusive security header audit)"
_TIMEOUT = 10


def _normalize(url: str) -> str:
    """Add an https:// scheme if the caller gave a bare host."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _extract_url(event) -> str:
    """Pull the target URL out of a direct-invoke payload OR an API Gateway event."""
    if not isinstance(event, dict):
        return "example.com"

    # Direct invoke: {"url": "..."}
    if event.get("url"):
        return str(event["url"])

    # API Gateway proxy: query string parameters
    qs = event.get("queryStringParameters") or {}
    if isinstance(qs, dict) and qs.get("url"):
        return str(qs["url"])

    # API Gateway proxy: JSON body (may be a string, possibly base64-encoded)
    body = event.get("body")
    if body:
        try:
            if event.get("isBase64Encoded"):
                import base64

                body = base64.b64decode(body).decode("utf-8", "replace")
            if isinstance(body, str):
                body = json.loads(body)
            if isinstance(body, dict) and body.get("url"):
                return str(body["url"])
        except (ValueError, TypeError):
            pass

    return "example.com"


def _fetch(url: str) -> urllib.request.addinfourl:
    """GET the url with a browser-like User-Agent. urllib follows redirects for GET."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA}, method="GET")
    return urllib.request.urlopen(req, timeout=_TIMEOUT)


def _extract_cookies(resp) -> list[dict]:
    """Parse Set-Cookie header(s) into simple security-flag dicts using stdlib only."""
    # Get every Set-Cookie line (there can be several).
    try:
        raw_lines = resp.headers.get_all("Set-Cookie") or []
    except AttributeError:
        one = resp.headers.get("Set-Cookie")
        raw_lines = [one] if one else []

    cookies: list[dict] = []
    for line in raw_lines:
        if not line:
            continue
        low = line.lower()
        secure = "secure" in low
        httponly = "httponly" in low

        # Find a SameSite=<value> token, case-insensitively.
        samesite = None
        for part in line.split(";"):
            part = part.strip()
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1].strip() or None
                break

        # Cookie name: first token before '=' (robust parse via SimpleCookie).
        name = "<cookie>"
        try:
            jar = SimpleCookie()
            jar.load(line)
            if jar:
                name = next(iter(jar.keys()))
        except Exception:
            first = line.split(";", 1)[0]
            if "=" in first:
                name = first.split("=", 1)[0].strip() or name

        cookies.append(
            {
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
            }
        )
    return cookies


def _check_https_redirect(host: str) -> bool | None:
    """Return True if http://host ends up on https, False if not, None if unknown."""
    if not host:
        return None
    try:
        resp = _fetch("http://" + host)
        final = resp.geturl()
        resp.close()
        return final.startswith("https://")
    except Exception:
        return None


def _scan(url: str) -> dict:
    """Fetch + analyze. Returns the result dict or {"error": ...}, never raises."""
    url = _normalize(url)
    try:
        resp = _fetch(url)
    except urllib.error.HTTPError as exc:
        # An HTTP error still carries a real response with headers we can grade.
        resp = exc
    except urllib.error.URLError as exc:
        return {"error": f"Could not scan {url}: {getattr(exc, 'reason', exc)}"}
    except Exception as exc:  # noqa: BLE001 - never let the handler raise
        return {"error": f"Could not scan {url}: {exc}"}

    try:
        final_url = resp.geturl() or url
        status_code = getattr(resp, "status", None) or getattr(resp, "code", 0) or 0
        headers = dict(resp.headers.items())
        cookies = _extract_cookies(resp)
    finally:
        try:
            resp.close()
        except Exception:
            pass

    present, missing = header_checks.analyze_headers(headers)
    cookie_issues = header_checks.analyze_cookies(cookies)
    https_redirect = _check_https_redirect(urlparse(final_url).netloc)

    report = header_checks.format_report(
        final_url=final_url,
        status_code=status_code,
        present=present,
        missing=missing,
        cookie_issues=cookie_issues,
        https_redirect=https_redirect,
    )
    letter, score = header_checks.compute_grade(missing, cookie_issues, https_redirect)

    return {"grade": letter, "score": score, "report": report, "url": final_url}


def lambda_handler(event, context):
    """AWS Lambda entry point. Scans the URL in the event and returns the result."""
    url = _extract_url(event)
    return _scan(url)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = lambda_handler({"url": target}, None)
    print(json.dumps(result, indent=2))
