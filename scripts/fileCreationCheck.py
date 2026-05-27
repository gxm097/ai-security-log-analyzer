import json
from pathlib import Path
from datetime import datetime

SUSPICIOUS_FILE = "jsonlFiles/suspicious_events.jsonl"
ACCOUNT_RISK_FILE = "jsonlFiles/account_risk_events.jsonl"

BASELINE_FILE = "jsonlFiles/file_baseline.json"
OUTPUT_FILE = "jsonlFiles/file_creation_events.jsonl"

IGNORE_DIRS = [
    ".cache",
    ".mozilla",
    ".config/google-chrome",
    ".local/share/Trash"
]


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


def get_target_users():
    users = set()

    suspicious_events = read_jsonl(SUSPICIOUS_FILE)
    account_risk_events = read_jsonl(ACCOUNT_RISK_FILE)

    for finding in suspicious_events:
        for event in finding.get("events", []):
            username = event.get("username")
            if username:
                users.add(username)

    for finding in account_risk_events:
        event = finding.get("event", finding)

        username = event.get("username")
        if username and username != "unknown":
            users.add(username)

    return users


def should_ignore(path):
    path_str = str(path)

    for ignore in IGNORE_DIRS:
        if ignore in path_str:
            return True

    return False


def scan_user_files(users):
    files = {}

    for username in users:
        home_path = Path(f"/home/{username}")

        if not home_path.exists():
            continue

        for path in home_path.rglob("*"):
            try:
                if path.is_file() and not should_ignore(path):
                    stat = path.stat()

                    files[str(path)] = {
                        "path": str(path),
                        "username": username,
                        "size_bytes": stat.st_size,
                        "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "created_or_changed_time": datetime.fromtimestamp(stat.st_ctime).isoformat()
                    }
            except PermissionError:
                continue

    return files


def load_baseline():
    if not Path(BASELINE_FILE).exists():
        return {}

    with open(BASELINE_FILE, "r") as file:
        return json.load(file)


def save_baseline(files):
    with open(BASELINE_FILE, "w") as file:
        json.dump(files, file, indent=2)


def main():
    target_users = get_target_users()

    if not target_users:
        with open(OUTPUT_FILE, "w") as outfile:
            outfile.write(json.dumps({
                "finding": "none",
                "message": "No suspicious users or created users were available for file creation checks.",
                "severity": "Low",
                "severity_score": 0,
                "severity_reasons": []
            }) + "\n")

        print("No target users found for file creation check.")
        return

    old_files = load_baseline()
    current_files = scan_user_files(target_users)

    new_files = []

    for path, metadata in current_files.items():
        if path not in old_files:
            new_files.append(metadata)

    with open(OUTPUT_FILE, "w") as outfile:
        if new_files:
            for file_event in new_files:
                finding = {
                    "finding": "file_creation_detected",
                    "username": file_event.get("username"),
                    "severity": "Medium",
                    "severity_score": 5,
                    "severity_reasons": [
                        "New file detected under suspicious or newly created user's home directory"
                    ],
                    "file": file_event
                }

                outfile.write(json.dumps(finding) + "\n")
        else:
            outfile.write(json.dumps({
                "finding": "none",
                "message": "No new files were detected for suspicious or newly created users.",
                "target_users": list(target_users),
                "severity": "Low",
                "severity_score": 0,
                "severity_reasons": []
            }) + "\n")

    save_baseline(current_files)

    print(f"File creation events written to {OUTPUT_FILE}")
    print(f"Target users checked: {list(target_users)}")
    print(f"New files detected: {len(new_files)}")


if __name__ == "__main__":
    main()
