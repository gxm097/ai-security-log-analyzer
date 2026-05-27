import json
import re
import subprocess
from datetime import datetime

OUTPUT_FILE = "jsonlFiles/active_ssh_sessions.jsonl"


def get_active_ssh_sessions():
    result = subprocess.run(
        ["who", "-u"],
        capture_output=True,
        text=True
    )

    sessions = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        if "(" not in line or ")" not in line:
            continue

        source_ip = line.split("(")[-1].split(")")[0]

        # Only count real remote IPv4 addresses.
        # This ignores local entries like:
        # (login screen), (tty2), (:0), localhost
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", source_ip):
            continue

        parts = line.split()

        username = parts[0]
        terminal = parts[1]
        login_date = parts[2] if len(parts) > 2 else "unknown"
        login_time = parts[3] if len(parts) > 3 else "unknown"

        sessions.append({
            "finding": "active_ssh_session",
            "username": username,
            "terminal": terminal,
            "login_time": f"{login_date} {login_time}",
            "source_ip": source_ip,
            "checked_at": datetime.now().isoformat(),
            "severity": "Medium",
            "severity_score": 5,
            "severity_reasons": [
                "Active remote SSH session currently open"
            ],
            "raw_session": line
        })

    return sessions


def main():
    sessions = get_active_ssh_sessions()

    with open(OUTPUT_FILE, "w") as outfile:
        if sessions:
            for session in sessions:
                outfile.write(json.dumps(session) + "\n")
        else:
            outfile.write(json.dumps({
                "finding": "none",
                "message": "No active remote SSH sessions were found.",
                "severity": "Low",
                "severity_score": 0,
                "severity_reasons": []
            }) + "\n")

    print(f"Active SSH sessions written to {OUTPUT_FILE}")
    print(f"Active remote SSH sessions found: {len(sessions)}")


if __name__ == "__main__":
    main()