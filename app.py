import streamlit as st
from anthropic import Anthropic
from dotenv import load_dotenv
import json
import requests

load_dotenv()

client = Anthropic()

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

system_prompt = """You are a cybersecurity analyst assistant with access to the National Vulnerability Database.
When asked to analyze a CVE, always use the lookup_cve tool to fetch live data first.
When asked follow-up questions or comparisons, use the conversation history to inform your answer.
For CVE analysis, respond with a JSON object in this exact format, no other text:
{
    "cve_id": "CVE ID",
    "severity": "Critical, High, Medium, or Low",
    "cvss_score": "CVSS score as a number if known, otherwise null",
    "attack_vector": "brief description of attack vector",
    "affected_systems": ["list", "of", "affected", "systems"],
    "summary": "2-3 sentence summary of the vulnerability",
    "mitigations": ["list", "of", "recommended", "mitigations"]
}
For follow-up questions or comparisons, respond in plain conversational text."""

def process_response(response, messages):
    if response.stop_reason == "tool_use":
        tool_use_block = next(b for b in response.content if b.type == "tool_use")
        tool_input = tool_use_block.input

        st.info(f"Fetching live data from NVD for {tool_input['cve_id']}...")
        tool_result = lookup_cve(tool_input["cve_id"])

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

        final_response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system_prompt,
            tools=tools,
            messages=messages
        )

        return final_response.content[0].text

    return response.content[0].text

def get_severity_color(severity):
    colors = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢"
    }
    return colors.get(severity, "⚪")

def display_threat_assessment(parsed):
    severity = parsed.get("severity", "Unknown")
    icon = get_severity_color(severity)

    st.markdown(f"### {icon} {parsed['cve_id']} — {severity} Severity")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("CVSS Score", parsed.get("cvss_score", "N/A"))
    with col2:
        st.metric("Severity", severity)

    st.markdown("**Attack Vector**")
    st.write(parsed.get("attack_vector", "N/A"))

    st.markdown("**Affected Systems**")
    for system in parsed.get("affected_systems", []):
        st.write(f"- {system}")

    st.markdown("**Summary**")
    st.write(parsed.get("summary", "N/A"))

    st.markdown("**Mitigations**")
    for mitigation in parsed.get("mitigations", []):
        st.write(f"- {mitigation}")

# Page config
st.set_page_config(
    page_title="Cybersecurity Triage Assistant",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cybersecurity Triage Assistant")
st.caption("Powered by Claude + NVD. Enter a CVE ID to analyze, or ask follow-up questions.")

# Initialize session state
if "messages" not in st.session_state:
    st.session_state.messages = []
if "display_history" not in st.session_state:
    st.session_state.display_history = []

# Display conversation history
for entry in st.session_state.display_history:
    with st.chat_message(entry["role"]):
        if entry["role"] == "assistant" and entry.get("is_json"):
            display_threat_assessment(entry["parsed"])
        else:
            st.write(entry["content"])

# Chat input
user_input = st.chat_input("Enter a CVE ID (e.g. CVE-2021-44228) or ask a question...")

if user_input:
    # Display user message
    with st.chat_message("user"):
        st.write(user_input)

    st.session_state.display_history.append({
        "role": "user",
        "content": user_input
    })

    st.session_state.messages.append({
        "role": "user",
        "content": user_input
    })

    # Get response
    with st.chat_message("assistant"):
        with st.spinner("Analyzing..."):
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1024,
                system=system_prompt,
                tools=tools,
                messages=st.session_state.messages
            )

            result = process_response(response, st.session_state.messages)
            st.session_state.messages.append({
                "role": "assistant",
                "content": result
            })

            # Try to parse as JSON
            cleaned = result.replace("```json", "").replace("```", "").strip()
            try:
                parsed = json.loads(cleaned)
                display_threat_assessment(parsed)
                st.session_state.display_history.append({
                    "role": "assistant",
                    "is_json": True,
                    "parsed": parsed,
                    "content": result
                })
            except json.JSONDecodeError:
                st.write(result)
                st.session_state.display_history.append({
                    "role": "assistant",
                    "is_json": False,
                    "content": result
                })
