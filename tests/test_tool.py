"""Offline tests for security_headers_tool._scan with HTTP fully mocked.

No real network calls are made: security_headers_tool.requests.get is
monkeypatched to return fake Response objects.
"""
from __future__ import annotations

import requests

import security_headers_tool


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeCookie:
    """Mimics the parts of a requests cookie that _extract_cookies reads."""

    def __init__(self, name, secure=False, httponly=False, samesite=None):
        self.name = name
        self.secure = secure
        self._httponly = httponly
        self._rest = {}
        if samesite is not None:
            self._rest["SameSite"] = samesite

    def has_nonstandard_attr(self, attr):
        if attr.lower() == "httponly":
            return self._httponly
        return False


class FakeResponse:
    """Mimics the parts of requests.Response that _scan reads."""

    def __init__(self, headers=None, status_code=200, url="https://example.com",
                 cookies=None):
        self.headers = headers or {}
        self.status_code = status_code
        self.url = url
        self.cookies = cookies or []


# ---------------------------------------------------------------------------
# Successful scan
# ---------------------------------------------------------------------------
def test_scan_success_report(monkeypatch):
    main_response = FakeResponse(
        headers={
            # One present security header (case varied to exercise the logic).
            "strict-transport-security": "max-age=63072000; includeSubDomains",
            "Content-Type": "text/html",
        },
        status_code=200,
        url="https://example.com/",
        cookies=[FakeCookie("sid", secure=False, httponly=False, samesite=None)],
    )

    def fake_get(url, **kwargs):
        # The second call (_check_https_redirect) fetches http://<host>;
        # simulate a server that upgrades http -> https.
        if url.startswith("http://"):
            return FakeResponse(url="https://example.com/")
        return main_response

    monkeypatch.setattr(security_headers_tool.requests, "get", fake_get)

    report = security_headers_tool._scan("https://example.com")

    assert isinstance(report, str)
    # Graded report.
    assert "GRADE:" in report
    # A present header appears in the present section.
    assert "Strict-Transport-Security:" in report
    # A missing header contributes its exact fix line (CSP was absent).
    assert "Content-Security-Policy: default-src 'self'" in report
    # The insecure cookie is flagged.
    assert "sid" in report
    # HTTPS redirect detected as working.
    assert "redirected to https://" in report


def test_scan_prepends_https_scheme(monkeypatch):
    seen = {}

    def fake_get(url, **kwargs):
        if url.startswith("http://"):
            return FakeResponse(url="https://example.com/")
        seen["main_url"] = url
        return FakeResponse(url="https://example.com/", status_code=200)

    monkeypatch.setattr(security_headers_tool.requests, "get", fake_get)

    # Pass a bare host; _scan should prepend https://
    security_headers_tool._scan("example.com")
    assert seen["main_url"] == "https://example.com"


# ---------------------------------------------------------------------------
# Connection failure
# ---------------------------------------------------------------------------
def test_scan_connection_error_returns_could_not_scan(monkeypatch):
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(security_headers_tool.requests, "get", boom)

    report = security_headers_tool._scan("https://doesnotexist.example")
    assert isinstance(report, str)
    assert report.startswith("Could not scan")
