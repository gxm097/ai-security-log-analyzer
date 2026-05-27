import json
import subprocess
from datetime import datetime

OUTPUT_FILE = "jsonlFiles/process_events.jsonl"

SUSPICIOUS_KEYWORDS = [
    "nc ",
    "netcat",
    "ncat",
    "bash -i",
    "/dev/tcp",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "php -r",
    "wget ",
    "curl ",
    "chmod +x",
    "base64 -d",
    "sshpass",
    "socat",
    "mkfifo",
]


def get_processes():
    result = subprocess.run(
        ["ps", "auxww"],
        capture_output=True,
        text=True
    )

    return result.stdout.splitlines()[1:]


def analyze_process(line):
    lower_line = line.lower()
    matched_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_line:
            matched_keywords.append(keyword.strip())

    if not matched_keywords:
        return None

    parts = line.split(None, 10)

    if len(parts) < 11:
        return None

    user = parts[0]
    pid = parts[1]
    cpu = parts[2]
    mem = parts[3]
    command = parts[10]

    severity = "Medium"
    score = 5

    high_risk_terms = [
        "bash -i",
        "/dev/tcp",
        "mkfifo",
        "base64 -d",
        "nc ",
        "netcat",
        "ncat",
    ]

    if any(term in lower_line for term in high_risk_terms):
        severity = "High"
        score = 8

    return {
        "finding": "suspicious_process_detected",
        "user": user,
        "pid": pid,
        "cpu": cpu,
        "memory": mem,
        "command": command,
        "matched_keywords": matched_keywords,
        "severity": severity,
        "severity_score": score,
        "severity_reasons": [
            "Running process matched suspicious command pattern"
        ],
        "checked_at": datetime.now().isoformat(),
        "raw_process": line
    }


def main():
    processes = get_processes()
    findings = []

    for process in processes:
        finding = analyze_process(process)

        if finding:
            findings.append(finding)

    with open(OUTPUT_FILE, "w") as outfile:
        if findings:
            for finding in findings:
                outfile.write(json.dumps(finding) + "\n")
        else:
            outfile.write(json.dumps({
                "finding": "none",
                "message": "No suspicious running processes were detected.",
                "severity": "Low",
                "severity_score": 0,
                "severity_reasons": []
            }) + "\n")

    print(f"Process events written to {OUTPUT_FILE}")
    print(f"Suspicious processes found: {len(findings)}")


if __name__ == "__main__":
    main()
