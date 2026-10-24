# Reusable pattern: give your agent a security-header inspection tool

This is the reusable asset from this project. Any builder can drop this tool
into their own Strands agent to give it the ability to audit a website's HTTP
security headers.

## 1. The tool

The tool is two small files: [`security_headers_tool.py`](security_headers_tool.py)
(the Strands `@tool` + HTTP fetching) and [`header_checks.py`](header_checks.py)
(pure, unit-tested analysis + A–F grading, no network). It exposes a single
Strands `@tool`:

```python
@tool
def scan_security_headers(url: str) -> str:
    """Scan a website's HTTP response headers for missing security headers."""
    ...
```

It has no dependency on the rest of this project — just `strands` and `requests`.

## 2. Wire it into any Strands agent (3 lines)

```python
from strands import Agent
from strands.models import BedrockModel
from security_headers_tool import scan_security_headers   # <-- the reusable bit

agent = Agent(
    model=BedrockModel(model_id="us.amazon.nova-pro-v1:0", region_name="us-east-1"),
    tools=[scan_security_headers],                          # <-- register it
)

agent("Check the security headers on example.com")
```

That is the entire integration. The agent decides on its own when to call the
tool, based on the tool's name and docstring.

## 3. How to adapt it

- **Add more headers:** extend the `SECURITY_HEADERS` dict at the top of the
  file — add the header name, a `severity`, a `why`, and a `fix`.
- **Change the model:** swap `model_id` for any Bedrock model you have access to
  (e.g. `us.amazon.nova-2-lite-v1:0`, or an Anthropic Claude model id — Claude
  needs a one-time use-case form in the Bedrock console).
- **Make it a cloud tool:** already done — `lambda/` contains the same scanner
  as an AWS Lambda (stdlib-only, SAM template included), and `tool_lambda.py`
  is a drop-in `@tool` that invokes it via boto3. Set `USE_LAMBDA_TOOL=1` to
  switch the agent over.

## 4. Why this pattern is useful

Header auditing is a common first step in web-app security reviews (OWASP
Secure Headers Project). Turning it into a drop-in agent tool means any
security or DevOps agent can gain real, grounded "look at the actual site"
ability instead of guessing from training data.
