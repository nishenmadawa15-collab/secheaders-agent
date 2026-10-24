# Demo video script (target: under 3 minutes)

Record your screen (OBS Studio is free) with your two terminals ready. Speak
naturally — this is a script to follow, not read word-for-word. Pick a site to
scan that you own or a well-known public site (e.g. `github.com`).

---

### Scene 1 — Intro (0:00 – 0:20)

**On screen:** your face cam or just the title/README.

**Say:**
> "Hi, I'm Madava. This is SecHeaders — a web-security agent I built with the
> Strands SDK and Amazon Bedrock. For the Weekend Challenge I gave it one new
> tool: the ability to scan a real website's security headers. Let me show you
> the before and the after."

---

### Scene 2 — BEFORE (0:20 – 1:00)

**On screen:** terminal running `python agent_before.py`.

**Type:**
> `can you check the security headers on github.com?`

**Say (while it answers):**
> "This is the agent *without* the tool. Notice — it can only give general
> advice. It can't actually look at github.com. It's guessing from training
> data. There's no real scan happening."

**On screen:** let the generic answer finish. Point out: "no real data."

---

### Scene 3 — AFTER (1:00 – 2:10)

**On screen:** second terminal running `python agent.py`.

**Type the exact same thing:**
> `can you check the security headers on github.com?`

**Say (while the tool runs):**
> "Same agent, same question — but now it has the `scan_security_headers` tool.
> Watch: it fetches the real site, reads the actual HTTP headers, cookies and
> redirect behaviour, and comes back with a **graded report — A to F** — which
> headers are missing, how serious each one is, and the exact header to add to
> fix it. This is grounded in the real response, not a guess."

**On screen:** point at the **GRADE** line first — it's the money shot.

**On screen:** highlight 1–2 findings, e.g. "missing Content-Security-Policy —
High", and the suggested fix line.

---

### Scene 4 — The tool + reusable pattern (2:10 – 2:45)

**On screen:** open `security_headers_tool.py`, scroll to the `@tool` function.

**Say:**
> "The whole tool is a single Strands `@tool` on top of a pure, unit-tested
> analysis module — 15 offline tests, all green. Any builder can drop it into
> their own agent in three lines, and the repo even includes a SAM template to
> run the same tool as an AWS Lambda. That's the reusable pattern: give any
> security agent the power to actually check a site."

---

### Scene 5 — Wrap (2:45 – 3:00)

**Say:**
> "One small, focused tool turned vague advice into a real audit. That's
> SecHeaders. Code and write-up are in the repo. Thanks for watching!"

---

## Checklist before you upload
- [ ] Video is **under 3 minutes**
- [ ] Shows the **before** (no tool) and **after** (with tool) clearly
- [ ] The scan output is readable on screen (increase terminal font size)
- [ ] Uploaded to YouTube/Vimeo as **Public or Unlisted** (not Private)
- [ ] Link copied for the submission's **demo** field
