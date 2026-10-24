"""SecHeaders Agent (AFTER) - a Strands + Amazon Bedrock agent that can scan
websites for missing HTTP security headers.

This is the "after" agent: the scan_security_headers tool is wired in, so the
agent can inspect a real website instead of only giving generic advice.

Run:  python agent.py
"""
import os

from strands import Agent
from strands.models import BedrockModel

# Local tool by default; set USE_LAMBDA_TOOL=1 to use the deployed AWS Lambda
# version instead (see lambda/DEPLOY.md and tool_lambda.py).
if os.getenv("USE_LAMBDA_TOOL") == "1":
    from tool_lambda import scan_security_headers_lambda as scan_security_headers
else:
    from security_headers_tool import scan_security_headers

SYSTEM_PROMPT = (
    "You are SecHeaders, a friendly web-security assistant. "
    "When the user asks about the security of a specific website, call the "
    "scan_security_headers tool to inspect its real HTTP response headers, "
    "then explain the results in plain language and list the most important "
    "fixes first. Only discuss non-intrusive header checks; never attempt or "
    "suggest exploitation. If no URL is given, answer from general knowledge."
)


def build_agent() -> Agent:
    model = BedrockModel(
        model_id=os.getenv("BEDROCK_MODEL_ID", "us.amazon.nova-pro-v1:0"),
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        temperature=0.3,
    )
    return Agent(model=model, tools=[scan_security_headers], system_prompt=SYSTEM_PROMPT)


def main() -> None:
    agent = build_agent()
    print("SecHeaders Agent (AFTER) ready. Ask me to scan a website, e.g.")
    print('  "Can you check the security headers on example.com?"')
    print("Type quit to exit.\n")
    while True:
        try:
            user = input("you > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if user.lower() in {"quit", "exit", "q"}:
            break
        if not user:
            continue
        agent(user)  # Strands streams the answer to the terminal
        print("\n")


if __name__ == "__main__":
    main()
