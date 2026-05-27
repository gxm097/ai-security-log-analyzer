import json
import requests

SUSPICIOUS_FILE = "jsonlFiles/suspicious_events.jsonl"
ACCOUNT_RISK_FILE = "jsonlFiles/account_risk_events.jsonl"
FILE_CREATION_FILE = "jsonlFiles/file_creation_events.jsonl"
PROCESS_FILE = "jsonlFiles/process_events.jsonl"
ACTIVE_SSH_FILE = "jsonlFiles/active_ssh_sessions.jsonl"
SSH_SUMMARY_FILE = "jsonlFiles/ssh_activity_summary.jsonl"

OUTPUT_FILE = "ai_report.txt"

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:7b"


def read_jsonl(path):
    events = []

    try:
        with open(path, "r") as file:
            for line in file:
                if line.strip():
                    events.append(json.loads(line))
    except FileNotFoundError:
        print(f"File not found: {path}")

    return events


def remove_none_findings(events):
    return [
        event for event in events
        if event.get("finding") != "none"
    ]


def ask_ollama(suspicious_events, account_risk_events, file_creation_events, process_events, active_ssh_sessions, ssh_summary):
    prompt = f"""
You are a cybersecurity SOC analyst.

Analyze only the confirmed findings below.
Do not infer events that are not present.

SSH activity summary:
{json.dumps(ssh_summary, indent=2)}

Suspicious SSH events:
{json.dumps(suspicious_events, indent=2)}

Account risk events:
{json.dumps(account_risk_events, indent=2)}

Susicious process events:
{json.dumps(process_events, indent=2)}

File creation events:
{json.dumps(file_creation_events, indent=2)}

Active SSH sessions:
{json.dumps(active_ssh_sessions, indent=2)}

Return:
1. Executive summary
2. SSH activity summary
3. Suspicious SSH findings
4. Users created
5. Password changes
6. File creation activity
7. Running process findings
8. Active SSH sessions
9. Severity assessment
10. Recommended next steps

Rules:
- If a section has an empty list [], say no confirmed findings were found for that section.
- Do not count placeholder "none" records as real findings.
- Do not analyze raw logs.
- Do not invent cron jobs, users, sessions, files, or password changes.
- If attempts_before_success is greater than 0, clearly state how many failed SSH attempts happened before login.
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=180
    )

    response.raise_for_status()
    return response.json()["response"]


def main():
    suspicious_events = remove_none_findings(read_jsonl(SUSPICIOUS_FILE))
    account_risk_events = remove_none_findings(read_jsonl(ACCOUNT_RISK_FILE))
    file_creation_events = remove_none_findings(read_jsonl(FILE_CREATION_FILE))
    process_events = remove_none_findings(read_jsonl(PROCESS_FILE))
    active_ssh_sessions = remove_none_findings(read_jsonl(ACTIVE_SSH_FILE))
    ssh_summary = read_jsonl(SSH_SUMMARY_FILE)

    print(f"Loaded {len(suspicious_events)} suspicious SSH findings")
    print(f"Loaded {len(account_risk_events)} account risk findings")
    print(f"Loaded {len(file_creation_events)} file creation findings")
    print(f"Loaded {len(process_events)} suspicious process findings")
    print(f"Loaded {len(active_ssh_sessions)} active SSH sessions")
    print(f"Loaded {len(ssh_summary)} SSH summary records")

    analysis = ask_ollama(
        suspicious_events,
        account_risk_events,
        file_creation_events,
        process_events,
   	active_ssh_sessions,
        ssh_summary
    )

    with open(OUTPUT_FILE, "w") as outfile:
        outfile.write(analysis)

    print(f"AI report written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
