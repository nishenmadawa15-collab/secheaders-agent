# Setup & run (AWS Bedrock)

Total time: ~10 minutes.

> **Good news (since Oct 2025):** Amazon Bedrock now auto-enables serverless
> foundation models — the old "Model access" console page is retired. Amazon
> **Nova** models need **no enabling step**. (Anthropic Claude models would need
> a one-time use-case form in the console; not needed for this project.)

The code pins `region_name="us-east-1"` — your console can sit in any region
(e.g. ap-south-1); it doesn't matter. CloudWatch logs and quotas for these
calls live in **us-east-1** though.

## Step 1 — Credentials

```bash
aws configure            # Access key ID, Secret key, default region us-east-1
aws sts get-caller-identity   # must print your account — verifies creds work
```

IAM: for a personal test account, attach **AmazonBedrockFullAccess** to your
user. (Minimal alternative: `bedrock:InvokeModel`,
`bedrock:InvokeModelWithResponseStream` and `bedrock:GetInferenceProfile` on
the inference-profile **and** foundation-model ARNs.)

## Step 2 — Budget alert (do not skip)

Console → **Billing and Cost Management** → **Budgets** → **Create budget** →
Zero-spend or small monthly amount (e.g. $5) → add your email.

## Step 3 — Pre-flight check (30 seconds)

```bash
aws bedrock list-foundation-models --region us-east-1 \
  --query 'modelSummaries[?contains(modelId,`nova`)].modelId'
```

Then a 3-line smoke test:

```python
import boto3
c = boto3.client("bedrock-runtime", region_name="us-east-1")
print(c.converse(modelId="us.amazon.nova-pro-v1:0",
                 messages=[{"role":"user","content":[{"text":"hi"}]}])["output"])
```

If that prints a reply, Bedrock is fully working.

## Step 4 — Install & run

```bash
cd secheaders-agent
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python agent_before.py    # the BEFORE agent (record this for the demo)
python agent.py           # the AFTER agent (with the tool)
```

Ask both: `can you check the security headers on github.com?`

## Model notes

Default model: **`us.amazon.nova-pro-v1:0`** — low cost and a reliable
tool-caller (Nova **Lite** is cheaper but community experience says it is
unreliable for agentic tool use, which is the whole point of this demo).
Swap per-run with:

```bash
BEDROCK_MODEL_ID=us.amazon.nova-2-lite-v1:0 python agent.py
```

Keep the `us.` prefix — Nova has no in-region on-demand invocation, so the
bare `amazon.nova-pro-v1:0` id fails (see table).

## Troubleshooting

| Error | Fix |
|-------|-----|
| `ValidationException: ...on-demand throughput isn't supported. Retry with ... an inference profile` | You used a bare model id. Use the `us.` prefixed id (the code's default already does). |
| `ValidationException: provided model identifier is invalid` | `us.` profile id called in a non-US region. Keep `region_name="us-east-1"`. |
| `AccessDeniedException` | IAM user lacks invoke permissions. Attach **AmazonBedrockFullAccess**. |
| `NoCredentialsError` / `ExpiredToken` | Re-run `aws configure`; verify with `aws sts get-caller-identity`. |
| `ThrottlingException` on the very first call | Some brand-new accounts get provisioned with **0 quota** for Bedrock. Check Service Quotas → Amazon Bedrock (us-east-1); if limits show 0, open an AWS support case. |
| Agent answers but never calls the tool | Model too weak for tool use — use `us.amazon.nova-pro-v1:0` (default) or stronger. |
| Tool prints a very low grade for a site you know is secure | You're behind a proxy/VPN that strips headers. Run on a normal network. |
