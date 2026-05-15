from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

client = Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system="You are a cybersecurity analyst assistant. When given a threat artifact such as a CVE description, log excerpt, or phishing email, you analyze it and provide a clear, structured threat assessment.",
    messages=[
        {
            "role": "user",
            "content": "Analyze this CVE: CVE-2021-44228, also known as Log4Shell. It is a remote code execution vulnerability in Apache Log4j 2."
        }
    ]
)

print(message.content[0].text)
