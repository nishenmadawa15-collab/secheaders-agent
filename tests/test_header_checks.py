"""Offline unit tests for the pure logic in header_checks.py.

No network, no AWS, no Bedrock — everything here operates on plain data.
"""
from __future__ import annotations

import header_checks


# ---------------------------------------------------------------------------
# analyze_headers
# ---------------------------------------------------------------------------
def test_analyze_headers_present_missing_split_case_insensitive():
    # Provide a mix: one header with its canonical casing, one lowercase
    # (to prove case-insensitivity), and leave the rest absent.
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",  # lowercase on purpose
        "X-Irrelevant": "ignored",
    }
    present, missing = header_checks.analyze_headers(headers)

    # Both supplied security headers should be counted as present regardless of case.
    assert any(p.startswith("Strict-Transport-Security:") for p in present)
    assert any(p.startswith("Content-Security-Policy:") for p in present)
    assert len(present) == 2

    # The value should be carried through from the (lowercase) input.
    csp_line = next(p for p in present if p.startswith("Content-Security-Policy:"))
    assert "default-src 'self'" in csp_line

    # The remaining 4 of the 6 graded headers are missing.
    missing_names = {m["name"] for m in missing}
    assert missing_names == {
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    }
    # Each missing dict carries the full metadata.
    for m in missing:
        assert set(m) >= {"name", "severity", "why", "fix"}


def test_analyze_headers_all_missing_when_empty():
    present, missing = header_checks.analyze_headers({})
    assert present == []
    assert len(missing) == len(header_checks.SECURITY_HEADERS)


# ---------------------------------------------------------------------------
# analyze_cookies
# ---------------------------------------------------------------------------
def test_analyze_cookies_insecure_cookie_reports_all_flaws():
    cookies = [
        {"name": "sid", "secure": False, "httponly": False, "samesite": None},
    ]
    issues = header_checks.analyze_cookies(cookies)
    assert len(issues) == 1
    issue = issues[0]
    assert "sid" in issue
    assert "no Secure flag" in issue
    assert "no HttpOnly flag" in issue
    assert "no SameSite attribute" in issue


def test_analyze_cookies_fully_secure_cookie_has_no_issues():
    cookies = [
        {"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"},
    ]
    assert header_checks.analyze_cookies(cookies) == []


def test_analyze_cookies_partial_flaws():
    cookies = [
        {"name": "a", "secure": True, "httponly": False, "samesite": "Strict"},
    ]
    issues = header_checks.analyze_cookies(cookies)
    assert len(issues) == 1
    assert "no HttpOnly flag" in issues[0]
    assert "no Secure flag" not in issues[0]
    assert "no SameSite attribute" not in issues[0]


# ---------------------------------------------------------------------------
# compute_grade
# ---------------------------------------------------------------------------
def test_compute_grade_all_present_is_perfect_A():
    letter, score = header_checks.compute_grade(
        missing=[], cookie_issues=[], https_redirect=True
    )
    assert (letter, score) == ("A", 100)


def test_compute_grade_two_high_missing_is_F_50():
    missing = [
        {"name": "Strict-Transport-Security", "severity": "High"},
        {"name": "Content-Security-Policy", "severity": "High"},
    ]
    letter, score = header_checks.compute_grade(
        missing=missing, cookie_issues=[], https_redirect=True
    )
    assert score == 50
    assert letter == "F"


def test_compute_grade_clamps_at_zero_for_everything_bad():
    # All 6 headers missing + many insecure cookies + no https redirect.
    missing = [{"name": n, "severity": meta["severity"]}
               for n, meta in header_checks.SECURITY_HEADERS.items()]
    cookie_issues = ["bad"] * 10
    letter, score = header_checks.compute_grade(
        missing=missing, cookie_issues=cookie_issues, https_redirect=False
    )
    assert score == 0
    assert letter == "F"


def test_compute_grade_single_low_missing_is_A_95():
    missing = [{"name": "Referrer-Policy", "severity": "Low"}]
    letter, score = header_checks.compute_grade(
        missing=missing, cookie_issues=[], https_redirect=True
    )
    assert score == 95
    assert letter == "A"


def test_compute_grade_none_https_redirect_no_penalty():
    # https_redirect is None (unknown) must not apply the -15 penalty.
    letter, score = header_checks.compute_grade(
        missing=[], cookie_issues=[], https_redirect=None
    )
    assert score == 100
    assert letter == "A"


# ---------------------------------------------------------------------------
# format_report
# ---------------------------------------------------------------------------
def test_format_report_contains_all_sections():
    headers = {"Strict-Transport-Security": "max-age=63072000"}
    present, missing = header_checks.analyze_headers(headers)
    cookie_issues = header_checks.analyze_cookies(
        [{"name": "sid", "secure": False, "httponly": False, "samesite": None}]
    )
    report = header_checks.format_report(
        final_url="https://example.com",
        status_code=200,
        present=present,
        missing=missing,
        cookie_issues=cookie_issues,
        https_redirect=True,
    )

    # Grade line and the computed letter.
    letter, score = header_checks.compute_grade(missing, cookie_issues, True)
    assert "GRADE:" in report
    assert f"GRADE: {letter}" in report

    # Each missing header must contribute a Fix line.
    for m in missing:
        assert m["fix"] in report
    assert "Fix: add header ->" in report

    # HTTPS redirect section (True branch).
    assert "HTTPS redirect:" in report
    assert "redirected to https://" in report

    # Cookie section present and reporting the insecure cookie.
    assert "Cookie security:" in report
    assert "sid" in report

    # Present header shows up under the present list.
    assert "Strict-Transport-Security:" in report


def test_format_report_https_redirect_false_and_warn():
    report = header_checks.format_report(
        final_url="http://example.com",
        status_code=200,
        present=[],
        missing=[],
        cookie_issues=[],
        https_redirect=False,
    )
    assert "NOT redirected to https://" in report
    # No cookies / all headers present branches.
    assert "no insecure cookies found" in report
    assert "All checked security headers are present" in report
