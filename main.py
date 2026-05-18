from anthropic import Anthropic
from dotenv import load_dotenv
import json

load_dotenv()

client = Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system="""You are a cybersecurity analyst assistant. When given a threat artifact, analyze it and respond ONLY with a JSON object in this exact format, no other text:
{
    "cve_id": "CVE ID if applicable, otherwise null",
    "severity": "Critical, High, Medium, or Low",
    "cvss_score": "CVSS score as a number if known, otherwise null",
    "attack_vector": "brief description of attack vector",
    "affected_systems": ["list", "of", "affected", "systems"],
    "summary": "2-3 sentence summary of the vulnerability",
    "mitigations": ["list", "of", "recommended", "mitigations"]
}""",
    messages=[
        {
            "role": "user",
            "content": "Analyze this CVE: CVE-2021-44228, also known as Log4Shell. It is a remote code execution vulnerability in Apache Log4j 2."
        }
    ]
)

raw = message.content[0].text
cleaned = raw.replace("```json", "").replace("```", "").strip()
parsed = json.loads(cleaned)

print("CVE ID:", parsed["cve_id"])
print("Severity:", parsed["severity"])
print("CVSS Score:", parsed["cvss_score"])
print("Attack Vector:", parsed["attack_vector"])
print("Affected Systems:", ", ".join(parsed["affected_systems"]))
print("\nSummary:", parsed["summary"])
print("\nMitigations:")
for m in parsed["mitigations"]:
    print(" -", m)
