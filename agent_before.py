"""SecHeaders Agent (BEFORE) - the same Bedrock-backed assistant, but with NO
tools wired in.

It can only give generic advice from the model's training data; it cannot
inspect a real website. Use this to record the "before" half of your
before/after demo: ask it to check a real site and watch it be unable to.

Run:  python agent_before.py
"""
import os

from strands import Agent
from strands.models import BedrockModel

SYSTEM_PROMPT = (
    "You are SecHeaders, a friendly web-security assistant. Answer questions "
    "about website security from your general knowledge."
)


def main() -> None:
    model = BedrockModel(
        model_id=os.getenv("BEDROCK_MODEL_ID", "us.amazon.nova-pro-v1:0"),
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        temperature=0.3,
    )
    agent = Agent(model=model, system_prompt=SYSTEM_PROMPT)  # <-- no tools
    print("SecHeaders Agent (BEFORE - no tools). Ask me to scan a website.")
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
        agent(user)
        print("\n")


if __name__ == "__main__":
    main()
