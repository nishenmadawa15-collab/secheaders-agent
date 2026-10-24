"""Reusable Strands tool: audit a URL's HTTP security posture.

Drop this file (plus header_checks.py) into any Strands Agents SDK project,
import `scan_security_headers`, and add it to your agent's `tools=[...]` list.
See REUSABLE_PATTERN.md for a copy-paste guide.

The check is NON-INTRUSIVE: it performs ordinary HTTP GET requests (exactly what
a browser does when it loads a page) and reads the responses. It does not probe,
fuzz, log in, or attack the target in any way.
"""
from __future__ import annotations

from urllib.parse import urlparse

import requests
from strands import tool

import header_checks

_UA = {"User-Agent": "SecHeaders-Agent/2.0 (+non-intrusive security header audit)"}
_TIMEOUT = 10


def _extract_cookies(resp: requests.Response) -> list[dict]:
    """Pull simple security-relevant flags out of the response cookies."""
    out = []
    for c in resp.cookies:
        out.append(
            {
                "name": c.name,
                "secure": bool(c.secure),
                "httponly": c.has_nonstandard_attr("HttpOnly")
                or c.has_nonstandard_attr("httponly"),
                "samesite": c._rest.get("SameSite") or c._rest.get("samesite"),
            }
        )
    return out


def _check_https_redirect(host: str) -> bool | None:
    """Return True if http://host redirects to https, False if not, None if unknown."""
    try:
        r = requests.get(
            f"http://{host}", timeout=_TIMEOUT, allow_redirects=True, headers=_UA
        )
        return r.url.startswith("https://")
    except requests.exceptions.RequestException:
        return None


def _scan(url: str) -> str:
    """Core scan logic (shared by the tool and the Lambda). Returns a report."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=_TIMEOUT, allow_redirects=True, headers=_UA)
    except requests.exceptions.SSLError:
        return f"Could not scan {url}: the site's TLS/SSL certificate could not be verified."
    except requests.exceptions.ConnectionError:
        return f"Could not scan {url}: connection failed (the site may be down or unreachable)."
    except requests.exceptions.Timeout:
        return f"Could not scan {url}: the request timed out after {_TIMEOUT} seconds."
    except requests.exceptions.RequestException as exc:
        return f"Could not scan {url}: {exc}"

    present, missing = header_checks.analyze_headers(dict(resp.headers))
    cookie_issues = header_checks.analyze_cookies(_extract_cookies(resp))
    https_redirect = _check_https_redirect(urlparse(resp.url).netloc)

    return header_checks.format_report(
        final_url=resp.url,
        status_code=resp.status_code,
        present=present,
        missing=missing,
        cookie_issues=cookie_issues,
        https_redirect=https_redirect,
    )


@tool
def scan_security_headers(url: str) -> str:
    """Audit a website's HTTP security posture and give it a grade.

    Fetches the given URL with ordinary HTTP GET requests (like a browser) and
    checks its security headers, cookie flags, and HTTP->HTTPS redirect, then
    returns a graded report (A-F). Use this whenever the user asks to check,
    scan, audit, or grade the security of a specific website.

    Args:
        url: The website to scan, e.g. "example.com" or "https://example.com".

    Returns:
        A human-readable report: a letter grade, present/missing security
        headers (each missing one with severity and the exact fix), the HTTPS
        redirect status, and any insecure cookies.
    """
    return _scan(url)


# Test the tool WITHOUT any AWS/Bedrock access:
#   python security_headers_tool.py github.com
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(_scan(target))
