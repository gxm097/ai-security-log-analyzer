import json
import re
from pathlib import Path
from datetime import datetime, timedelta

OUTPUT_FILE = "jsonlFiles/output.jsonl"

LOG_SOURCES = [
    ("/var/log/auth.log", "auth.log"),
    ("/var/log/syslog", "syslog"),
    ("/var/log/kern.log", "kern.log"),
    ("/var/log/ufw.log", "ufw.log"),
]

def get_time_window():
    print("\nHow far back do you want to check?")
    print("1. Last 15 minutes")
    print("2. Last 1 hour")
    print("3. Last 6 hours")
    print("4. Last 24 hours")
    print("5. Last 7 days")
    print("6. All available logs")

    choice = input("Choose an option (1-6): ").strip()

    now = datetime.now().astimezone()

    if choice == "1":
        return now - timedelta(minutes=15)
    elif choice == "2":
        return now - timedelta(hours=1)
    elif choice == "3":
        return now - timedelta(hours=6)
    elif choice == "4":
        return now - timedelta(hours=24)
    elif choice == "5":
        return now - timedelta(days=7)
    elif choice == "6":
        return None
    else:
        print("Invalid choice. Defaulting to last 24 hours.")
        return now - timedelta(hours=24)


def parse_syslog_timestamp(line):
    try:
        # ISO format example:
        # 2026-05-06T21:22:11.752594-05:00 GavNet sudo: ...
        iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}T[^\s]+)", line)
        if iso_match:
            return datetime.fromisoformat(iso_match.group(1))

        # Traditional syslog format example:
        # May  7 10:15:22 hostname sshd...
        current_year = datetime.now().year
        timestamp_text = line[:15]
        parsed = datetime.strptime(
            f"{current_year} {timestamp_text}",
            "%Y %b %d %H:%M:%S"
        )

        return parsed.astimezone()

    except ValueError:
        return None


def parse_line(line, source):
    lower_line = line.lower()

    parsed_time = parse_syslog_timestamp(line)

    event = {
        "source": source,
        "raw_log": line.strip(),
        "event_type": "unknown",
        "timestamp": parsed_time.isoformat() if parsed_time else None
    }

    # Failed SSH login
    failed_ssh_match = re.search(
        r"Failed password for (?:invalid user )?([^\s]+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2",
        line
    )

    if failed_ssh_match:
        event["event_type"] = "failed_ssh_login"
        event["username"] = failed_ssh_match.group(1)
        event["source_ip"] = failed_ssh_match.group(2)
        event["port"] = failed_ssh_match.group(3)
        return event

    # Accepted SSH login
    accepted_ssh_match = re.search(
        r"Accepted password for ([^\s]+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2",
        line
    )

    if accepted_ssh_match:
        event["event_type"] = "accepted_ssh_login"
        event["username"] = accepted_ssh_match.group(1)
        event["source_ip"] = accepted_ssh_match.group(2)
        event["port"] = accepted_ssh_match.group(3)
        return event

    # User creation through sudo command:
    # COMMAND=/usr/sbin/useradd testuser02
    useradd_match = re.search(
        r"COMMAND=.*(?:/usr/sbin/)?useradd\s+([^\s]+)",
        line
    )

    if useradd_match:
        event["event_type"] = "user_creation"
        event["username"] = useradd_match.group(1)

        actor_match = re.search(r"sudo:\s+([^\s:]+)\s+:", line)
        if actor_match:
            event["actor_user"] = actor_match.group(1)

        event["command"] = "useradd"
        return event

    # User creation through adduser command:
    # COMMAND=/usr/sbin/adduser testuser02
    adduser_match = re.search(
        r"COMMAND=.*(?:/usr/sbin/)?adduser\s+([^\s]+)",
        line
    )

    if adduser_match:
        event["event_type"] = "user_creation"
        event["username"] = adduser_match.group(1)

        actor_match = re.search(r"sudo:\s+([^\s:]+)\s+:", line)
        if actor_match:
            event["actor_user"] = actor_match.group(1)

        event["command"] = "adduser"
        return event

    # Password change through sudo command:
    # COMMAND=/usr/bin/passwd testuser02
    passwd_command_match = re.search(
        r"COMMAND=.*(?:/usr/bin/)?passwd\s+([^\s]+)",
        line
    )

    if passwd_command_match:
        event["event_type"] = "password_change"
        event["username"] = passwd_command_match.group(1)

        actor_match = re.search(r"sudo:\s+([^\s:]+)\s+:", line)
        if actor_match:
            event["actor_user"] = actor_match.group(1)

        event["command"] = "passwd"
        return event

    # Native useradd log:
    # useradd[12345]: new user: name=testuser
    if "new user:" in lower_line:
        event["event_type"] = "user_creation"

        user_match = re.search(r"name=([^,\s]+)", line)
        if user_match:
            event["username"] = user_match.group(1)

        return event

    # Native password changed log
    if (
        "password changed" in lower_line
        or "authentication token updated successfully" in lower_line
    ):
        event["event_type"] = "password_change"

        user_match = re.search(r"password changed for ([^\s]+)", line)
        if user_match:
            event["username"] = user_match.group(1)

        return event

    
    # Native password change log:
    # passwd[12099]: pam_unix(passwd:chauthtok): password changed for testuser04
    native_passwd_match = re.search(
        r"passwd\[\d+\]:.*password changed for ([^\s]+)",
        line
    )

    if native_passwd_match:
        event["event_type"] = "password_change"
        event["username"] = native_passwd_match.group(1)
        event["command"] = "passwd"
        return event
    
    # General sudo activity
    if "sudo:" in lower_line:
        event["event_type"] = "sudo_activity"

        user_match = re.search(r"sudo:\s+([^\s:]+)\s+:", line)
        if user_match:
            event["username"] = user_match.group(1)

        command_match = re.search(r"COMMAND=(.*)", line)
        if command_match:
            event["command"] = command_match.group(1)

        return event

    # PAM authentication failure
    if "authentication failure" in lower_line:
        event["event_type"] = "pam_auth_failure"

        user_match = re.search(r"user=([^\s]+)", line)
        rhost_match = re.search(r"rhost=(\d+\.\d+\.\d+\.\d+)", line)

        if user_match:
            event["username"] = user_match.group(1)

        if rhost_match:
            event["source_ip"] = rhost_match.group(1)

        return event

    # Firewall / denied events
    if "ufw" in lower_line or "blocked" in lower_line or "denied" in lower_line:
        event["event_type"] = "firewall_or_denied_activity"
        return event

    # System failure/error
    if "failed" in lower_line or "error" in lower_line:
        event["event_type"] = "system_error_or_failure"
        return event

    return event


def main():
    total_written = 0
    total_skipped_by_time = 0

    start_time = get_time_window()

    if start_time:
        print(f"\nChecking logs from: {start_time.isoformat()}")
    else:
        print("\nChecking all available logs")

    with open(OUTPUT_FILE, "w") as outfile:
        for log_path, source_name in LOG_SOURCES:
            path = Path(log_path)

            if not path.exists():
                print(f"Skipping missing log: {log_path}")
                continue

            try:
                with open(path, "r", errors="ignore") as infile:
                    for line in infile:
                        if not line.strip():
                            continue

                        event_time = parse_syslog_timestamp(line)

                        if start_time and event_time:
                            if event_time < start_time:
                                total_skipped_by_time += 1
                                continue

                        event = parse_line(line, source_name)
                        outfile.write(json.dumps(event) + "\n")
                        total_written += 1

            except PermissionError:
                print(f"Permission denied reading {log_path}. Try running with sudo.")

    print(f"\nWrote {total_written} events to {OUTPUT_FILE}")
    print(f"Skipped {total_skipped_by_time} events outside selected time window")

if __name__ == "__main__":
    main()