# SecHeaders Agent

An AI agent that audits a website's **HTTP security posture** and gives it a
**grade (A–F)** — built with the [Strands Agents SDK](https://strandsagents.com)
and **Amazon Bedrock**.

Submission for the AWS Builder Center **Weekend Challenge: Give your Agent a Tool**.

## The before / after story

**Before** (`agent_before.py`) — a Bedrock-backed chatbot with no tools. Ask it
*"are the security headers on my site OK?"* and it can only give generic advice.
It cannot look at a real website.

**After** (`agent.py`) — the same agent, plus **one new tool**:
`scan_security_headers(url)`. Now the agent fetches the real page and returns a
graded audit:

- **Security headers** — six OWASP-recommended headers (HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
  each missing one with a severity and the **exact header line to add**
- **HTTP → HTTPS redirect** check
- **Cookie security flags** — `Secure`, `HttpOnly`, `SameSite`
- A single **letter grade (A–F)** with a 0–100 score

```
you > can you check the security headers on example.com?

Security scan for https://example.com/ (HTTP 200)
GRADE: C  (72/100)

Security headers present (3/6):
  [OK]  Strict-Transport-Security: max-age=31536000
  ...
Security headers missing (3):
  [MISSING - High] Content-Security-Policy
      Fix: add header ->  Content-Security-Policy: default-src 'self'
  ...
HTTPS redirect:
  [OK]  http:// requests are redirected to https://
Cookie security:
  [WARN] Cookie 'sid': no HttpOnly flag, no SameSite attribute
```

## Architecture

```
 user ──► Strands Agent ──► Amazon Bedrock (Nova Pro)       ← the "brain" (AWS)
             │
             └──► scan_security_headers(url)                ← the ONE new tool
                     │                 (runs locally, or as an AWS Lambda)
                     ├── GET the site, read headers/cookies
                     └── header_checks.py  (pure logic: analysis + grade)
```

- **AWS services:** Amazon Bedrock (agent brain) + optional **AWS Lambda**
  (serverless deployment of the same tool — see `lambda/DEPLOY.md`).
- **The one new tool:** `scan_security_headers` in `security_headers_tool.py`.

## Files

| File | What it is |
|------|-----------|
| `agent.py` | The **after** agent (has the tool; `USE_LAMBDA_TOOL=1` switches to the Lambda version) |
| `agent_before.py` | The **before** agent (no tools) — for the demo contrast |
| `security_headers_tool.py` | The new tool — a reusable Strands `@tool` |
| `header_checks.py` | Pure, network-free analysis + grading logic (unit-tested) |
| `tool_lambda.py` | Same tool, but invoking the deployed AWS Lambda via boto3 |
| `lambda/` | Serverless deployment: handler, SAM template, deploy guide |
| `tests/` | Offline pytest suite (15 tests, no network/AWS needed) |
| `REUSABLE_PATTERN.md` | How anyone can drop this tool into their own agent |
| `SETUP_AWS.md` | Step-by-step: enable Bedrock, credentials, run |

## Quickstart

See **[SETUP_AWS.md](SETUP_AWS.md)** for the full AWS steps. Short version:

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# configure AWS creds (aws configure) and enable Bedrock model access, then:
python agent.py
```

Test the **tool alone — no AWS needed**:

```bash
python security_headers_tool.py github.com
```

Run the test suite (offline, no AWS needed):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Ethics & scope

This tool is **non-intrusive**. It performs ordinary HTTP GET requests (exactly
what a browser does when it loads a page) and reads the responses. It does
**not** probe, fuzz, log in, or attack anything. Scan sites you own or public
sites you have permission to check.

## Cost

Amazon Nova Pro is a low-cost Bedrock model (chosen over Nova Lite because it
is a markedly more reliable tool-caller) — a full demo costs a tiny fraction of
a dollar — and the Lambda free tier easily covers the optional serverless
version. Still, **set an AWS Budget alert** (see SETUP_AWS.md) so there are no
surprises.
