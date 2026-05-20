from anthropic import Anthropic
from dotenv import load_dotenv
import json
import requests

load_dotenv()

client = Anthropic()

# The actual function that fetches live CVE data from NVD
def lookup_cve(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url, headers={"User-Agent": "cybersec-assistant/1.0"})
    if response.status_code != 200:
        return {"error": f"NVD API returned status {response.status_code}"}
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return {"error": "CVE not found"}
    cve = vulnerabilities[0]["cve"]
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            cvss_data = metrics[version][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            break
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": cvss_severity,
        "published": cve.get("published", "Unknown")
    }

# Tell Claude what tools it has access to
tools = [
    {
        "name": "lookup_cve",
        "description": "Looks up a CVE by ID in the National Vulnerability Database and returns its description, CVSS score, severity, and publication date.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE ID to look up, e.g. CVE-2021-44228"
                }
            },
            "required": ["cve_id"]
        }
    }
]

# Initial message
messages = [
    {
        "role": "user",
        "content": "Analyze this CVE and give me a structured threat assessment: CVE-2023-44487"
    }
]

print("Sending request to Claude...")

# First API call - Claude decides whether to use a tool
response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system="""You are a cybersecurity analyst assistant. Always use the lookup_cve tool to fetch live data before analyzing a CVE. Respond ONLY with a JSON object in this exact format, no other text:
{
    "cve_id": "CVE ID",
    "severity": "Critical, High, Medium, or Low",
    "cvss_score": "CVSS score as a number if known, otherwise null",
    "attack_vector": "brief description of attack vector",
    "affected_systems": ["list", "of", "affected", "systems"],
    "summary": "2-3 sentence summary of the vulnerability",
    "mitigations": ["list", "of", "recommended", "mitigations"]
}""",
    tools=tools,
    messages=messages
)

# Check if Claude wants to use a tool
if response.stop_reason == "tool_use":
    tool_use_block = next(b for b in response.content if b.type == "tool_use")
    tool_name = tool_use_block.name
    tool_input = tool_use_block.input

    print(f"Claude is calling tool: {tool_name} with input: {tool_input}")

    # We run the actual function
    tool_result = lookup_cve(tool_input["cve_id"])
    print(f"NVD returned: {tool_result}")

    # Feed the result back to Claude
    messages.append({"role": "assistant", "content": response.content})
    messages.append({
        "role": "user",
        "content": [
            {
                "type": "tool_result",
                "tool_use_id": tool_use_block.id,
                "content": json.dumps(tool_result)
            }
        ]
    })

    # Second API call - Claude now forms its final response using live data
    final_response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system="""You are a cybersecurity analyst assistant. Always use the lookup_cve tool to fetch live data before analyzing a CVE. Respond ONLY with a JSON object in this exact format, no other text:
{
    "cve_id": "CVE ID",
    "severity": "Critical, High, Medium, or Low",
    "cvss_score": "CVSS score as a number if known, otherwise null",
    "attack_vector": "brief description of attack vector",
    "affected_systems": ["list", "of", "affected", "systems"],
    "summary": "2-3 sentence summary of the vulnerability",
    "mitigations": ["list", "of", "recommended", "mitigations"]
}""",
        tools=tools,
        messages=messages
    )

    raw = final_response.content[0].text

else:
    raw = response.content[0].text

# Parse and display
cleaned = raw.replace("```json", "").replace("```", "").strip()
parsed = json.loads(cleaned)

print("\n--- THREAT ASSESSMENT ---")
print("CVE ID:", parsed["cve_id"])
print("Severity:", parsed["severity"])
print("CVSS Score:", parsed["cvss_score"])
print("Attack Vector:", parsed["attack_vector"])
print("Affected Systems:", ", ".join(parsed["affected_systems"]))
print("\nSummary:", parsed["summary"])
print("\nMitigations:")
for m in parsed["mitigations"]:
    print(" -", m)
