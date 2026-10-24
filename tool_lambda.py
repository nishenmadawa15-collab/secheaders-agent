"""Strands tool that runs the security-header scan on AWS Lambda instead of locally.

This is a drop-in replacement for the local `scan_security_headers` tool: the
heavy lifting (the HTTP fetch + analysis) happens in the deployed Lambda, so the
local agent needs no network egress to the target site - only permission to call
the Lambda (`lambda:InvokeFunction`).

To swap it into agent.py, change the import and the tools list:

    # from security_headers_tool import scan_security_headers      # local
    from tool_lambda import scan_security_headers_lambda           # Lambda

    return Agent(
        model=model,
        tools=[scan_security_headers_lambda],   # instead of [scan_security_headers]
        system_prompt=SYSTEM_PROMPT,
    )

Configure via environment variables:
    LAMBDA_FUNCTION_NAME   name of the deployed function (default "secheaders-scan")
    AWS_REGION             region the function lives in    (default "us-east-1")
"""
from __future__ import annotations

import json
import os

import boto3
from strands import tool


@tool
def scan_security_headers_lambda(url: str) -> str:
    """Audit a website's HTTP security posture and give it a grade (via AWS Lambda).

    Invokes a deployed AWS Lambda that fetches the given URL with ordinary HTTP
    GET requests (like a browser) and checks its security headers, cookie flags,
    and HTTP->HTTPS redirect, then returns a graded report (A-F). Use this
    whenever the user asks to check, scan, audit, or grade the security of a
    specific website.

    Args:
        url: The website to scan, e.g. "example.com" or "https://example.com".

    Returns:
        A human-readable report: a letter grade, present/missing security
        headers (each missing one with severity and the exact fix), the HTTPS
        redirect status, and any insecure cookies.
    """
    function_name = os.getenv("LAMBDA_FUNCTION_NAME", "secheaders-scan")
    region = os.getenv("AWS_REGION", "us-east-1")

    try:
        client = boto3.client("lambda", region_name=region)
        response = client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"url": url}).encode("utf-8"),
        )
    except Exception as exc:  # noqa: BLE001 - surface a readable error to the agent
        return f"Could not invoke Lambda '{function_name}' in {region}: {exc}"

    # A function-level error (unhandled exception inside the Lambda) is flagged here.
    if response.get("FunctionError"):
        raw = b""
        try:
            raw = response["Payload"].read()
        except Exception:
            pass
        return (
            f"Lambda '{function_name}' returned an error: "
            f"{raw.decode('utf-8', 'replace') or response['FunctionError']}"
        )

    try:
        payload = response["Payload"].read()
        result = json.loads(payload)
    except (KeyError, ValueError, TypeError) as exc:
        return f"Could not parse Lambda response from '{function_name}': {exc}"

    if isinstance(result, dict):
        if result.get("report"):
            return result["report"]
        if result.get("error"):
            return result["error"]

    return f"Unexpected Lambda response from '{function_name}': {result!r}"
