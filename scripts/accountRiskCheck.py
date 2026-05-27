import json
from datetime import datetime

INPUT_FILE = "jsonlFiles/output.jsonl"
OUTPUT_FILE = "jsonlFiles/account_risk_events.jsonl"

POST_LOGIN_WINDOW_MINUTES = 10


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


def parse_time(event):
    timestamp = event.get("timestamp")
    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def is_login_event(event):
    return event.get("event_type") == "accepted_ssh_login"


def is_sensitive_activity(event):
    return event.get("event_type") in [
        "user_creation",
        "password_change",
        "sensitive_file_change"
    ]


def base_finding_for_activity(activity):
    event_type = activity.get("event_type")

    if event_type == "user_creation":
        return {
            "finding": "user_creation_detected",
            "username": activity.get("username"),
            "actor_user": activity.get("actor_user"),
            "timestamp": activity.get("timestamp"),
            "severity": "High",
            "severity_score": 8,
            "severity_reasons": ["User creation event found in logs"],
            "event": activity
        }

    if event_type == "password_change":
        return {
            "finding": "password_change_detected",
            "username": activity.get("username"),
            "actor_user": activity.get("actor_user"),
            "timestamp": activity.get("timestamp"),
            "severity": "Medium",
            "severity_score": 6,
            "severity_reasons": ["Password change event found in logs"],
            "event": activity
        }

    if event_type == "sensitive_file_change":
        return {
            "finding": "sensitive_file_change_detected",
            "username": activity.get("username"),
            "timestamp": activity.get("timestamp"),
            "severity": "Medium",
            "severity_score": 6,
            "severity_reasons": ["Sensitive file change event found"],
            "event": activity
        }

    return None


def calculate_post_login_severity(minutes_after_login, event_type):
    score = 0
    reasons = []

    if event_type == "user_creation":
        score += 6
        reasons.append("User creation detected")

    if event_type == "password_change":
        score += 5
        reasons.append("Password change detected")

    if event_type == "sensitive_file_change":
        score += 5
        reasons.append("Sensitive file change detected")

    if minutes_after_login <= 10:
        score += 4
        reasons.append("Sensitive activity occurred shortly after login")

    if minutes_after_login <= 3:
        score += 2
        reasons.append("Sensitive activity occurred very shortly after login")

    if score >= 9:
        severity = "High"
    elif score >= 5:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity, reasons


def main():
    events = read_jsonl(INPUT_FILE)

    login_events = []
    sensitive_events = []
    findings = []

    for event in events:
        if is_login_event(event):
            login_events.append(event)

        if is_sensitive_activity(event):
            sensitive_events.append(event)

            base_finding = base_finding_for_activity(event)
            if base_finding:
                findings.append(base_finding)

    for login in login_events:
        login_time = parse_time(login)

        if not login_time:
            continue

        login_user = login.get("username")
        login_ip = login.get("source_ip")

        for activity in sensitive_events:
            activity_time = parse_time(activity)

            if not activity_time:
                continue

            activity_user = activity.get("username", login_user)
            raw_log = activity.get("raw_log", "")

            same_user = (
                activity_user == login_user
                or (login_user and login_user in raw_log)
            )

            minutes_after = (activity_time - login_time).total_seconds() / 60

            if (
                same_user
                and minutes_after >= 0
                and minutes_after <= POST_LOGIN_WINDOW_MINUTES
            ):
                score, severity, reasons = calculate_post_login_severity(
                    minutes_after,
                    activity.get("event_type")
                )

                findings.append({
                    "finding": "post_login_suspicious_activity",
                    "username": login_user,
                    "source_ip": login_ip,
                    "activity_type": activity.get("event_type"),
                    "minutes_after_login": round(minutes_after, 2),
                    "window_minutes": POST_LOGIN_WINDOW_MINUTES,
                    "severity": severity,
                    "severity_score": score,
                    "severity_reasons": reasons,
                    "login_event": login,
                    "activity_event": activity
                })

    with open(OUTPUT_FILE, "w") as outfile:
        if findings:
            for finding in findings:
                outfile.write(json.dumps(finding) + "\n")
        else:
            outfile.write(json.dumps({
                "finding": "none",
                "message": "No user creation, password change, sensitive file change, or post-login suspicious activity was detected.",
                "severity": "Low",
                "severity_score": 0,
                "severity_reasons": []
            }) + "\n")

    print(f"Account risk events written to {OUTPUT_FILE}")
    print(f"Sensitive events found: {len(sensitive_events)}")
    print(f"Total findings written: {len(findings)}")


if __name__ == "__main__":
    main()