# SecHeaders Agent: giving a security assistant the power to actually look

*My entry for the Weekend Challenge: Give your Agent a Tool.*

> Suggested Builder Center tags: `#security` `#strands-agents` `#amazon-bedrock`
> `#agents` `#aws-lambda`

## The agent I started with

I started with a small web-security assistant built on the **Strands Agents
SDK**, with **Amazon Bedrock** as its brain (`agent_before.py` in the repo). You
could chat with it about web security and it gave reasonable, general advice —
"you should set a Content-Security-Policy", "HSTS is a good idea", and so on.

But it had one big limitation: **it could not look at a real website.** Ask it
*"are the security headers on my site OK?"* and it could only talk in
generalities — guessing from training data, not from the actual site.

## The one new tool I added — and why (what's new)

I gave it a single, focused tool: **`scan_security_headers(url)`**
(`security_headers_tool.py`). When the agent gets a question about a specific
site, it calls this tool. The tool performs ordinary HTTP GET requests — exactly
what a browser does when it loads the page — and audits three things, rolled
into one **letter grade (A–F)** with a 0–100 score:

1. **Security headers** — six headers from the OWASP Secure Headers guidance:
   Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **HTTP → HTTPS redirect** — does plain `http://` traffic get upgraded?
3. **Cookie security flags** — `Secure`, `HttpOnly`, `SameSite` on every cookie

For every gap it returns the severity, why it matters, and the **exact header
line to add** — so the agent doesn't just find problems, it hands you the fix.

I picked this tool because header auditing is the fast, non-intrusive first step
of almost every web-app security review — the perfect capability to move from
"the model guesses" to "the agent checks." It is safe by design: it only reads
public response headers; it never probes, logs in, or attacks anything.

## How the tool is wired in (craft & execution)

- The tool is a Strands **`@tool`** whose docstring tells the model when to call
  it; the agent decides on its own, with no routing code (`agent.py`).
- All analysis and grading lives in a **pure, network-free module**
  (`header_checks.py`) — which is why the whole pipeline is covered by an
  **offline pytest suite: 15/15 passing** (`tests/`), no AWS or network needed.
- The model is **Amazon Bedrock** `us.amazon.nova-pro-v1:0` (chosen over Nova
  Lite after reading that Lite is an unreliable tool-caller — tool use is the
  entire point here).
- The same tool ships two ways: running locally, or as an **AWS Lambda**
  (stdlib-only handler + SAM template in `lambda/`); set `USE_LAMBDA_TOOL=1`
  and the agent invokes the serverless version via `boto3` (`tool_lambda.py`).

## Before vs after

**Before** (no tool):
> *"Can you check the security headers on example.com?"*
> → "I can't inspect live sites, but in general you should have CSP, HSTS,
> X-Frame-Options..." — generic and unverifiable.

**After** (with the tool):
> *"Can you check the security headers on example.com?"*
> → "I scanned example.com — **grade C (72/100)**. It has HSTS and
> X-Content-Type-Options, but it's **missing Content-Security-Policy (High)**
> and **X-Frame-Options (Medium)**, and the session cookie has no HttpOnly
> flag. Add these headers: ..." — specific, grounded in the real response.

Same agent, same model, same question. One tool turned vague advice into a
real audit.

## By the numbers

One new tool · 6 security headers + cookie flags + HTTPS redirect in every scan
· a graded A–F report in a couple of seconds · **15/15 offline tests passing** ·
2 deployment modes (local and Lambda) · roughly 300 lines of focused Python.

## Steal this pattern (reuse it)

Adding real header-auditing to **your** agent is three lines:

```python
from security_headers_tool import scan_security_headers
agent = Agent(model=BedrockModel(model_id="us.amazon.nova-pro-v1:0",
                                 region_name="us-east-1"),
              tools=[scan_security_headers])
agent("Check the security headers on example.com")
```

`security_headers_tool.py` + `header_checks.py` are self-contained — copy them
in, register the tool, done. `REUSABLE_PATTERN.md` in the repo covers adapting
the header list, swapping models, and the Lambda variant.

## Standing on giants — and what's actually new here

Header scanning itself is a solved problem: [securityheaders.com](https://securityheaders.com)
(Scott Helme) has graded response headers for years, and MDN's HTTP Observatory
scores sites 0–100 — my A–F scale follows that familiar convention deliberately.
What this project adds is the **agent integration**: one conversational loop
that scans, explains each finding in plain language, prioritises, and hands you
the exact fix — packaged as a reusable Strands tool pattern any builder can
drop into their own agent.

## The hardest decision, and honest limitations

The hardest engineering decision was keeping the analysis **pure and offline**:
splitting fetching (`security_headers_tool.py`) from logic (`header_checks.py`)
made the grading unit-testable without network — that's what makes the 15-test
suite possible — at the cost of a slightly less "clever-looking" one-file tool.

Limitations, honestly: header *presence* isn't full security (a weak CSP still
"passes"); the scan covers one page, not a whole site; and the grade is a
heuristic, not a pentest. Those are the next things I'd build.

## AWS services used

**Amazon Bedrock** (agent reasoning — `us.amazon.nova-pro-v1:0`) and
**AWS Lambda** (optional serverless deployment of the tool, SAM template
included).

---

**Repo:** <add your GitHub link>
**Demo video:** <add your YouTube link, under 3 minutes>
