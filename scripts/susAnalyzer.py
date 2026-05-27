import json
from collections import Counter, defaultdict
from datetime import datetime

INPUT_FILE = "jsonlFiles/output.jsonl"
OUTPUT_FILE = "jsonlFiles/suspicious_events.jsonl"
SSH_SUMMARY_FILE = "jsonlFiles/ssh_activity_summary.jsonl"

failed_by_ip = Counter()
accepted_by_ip = Counter()
failed_by_user = Counter()
accepted_by_user = Counter()

failed_events_by_ip = defaultdict(list)
accepted_events_by_ip = defaultdict(list)

all_ssh_events = []


def parse_timestamp(event):
    timestamp = event.get("timestamp")

    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def calculate_attempts_before_success(ip):
    """
    Counts failed SSH attempts from the same IP before the first successful SSH login.
    """

    if not accepted_events_by_ip[ip]:
        return 0

    first_success = min(
        accepted_events_by_ip[ip],
        key=lambda event: parse_timestamp(event) or datetime.max
    )

    success_time = parse_timestamp(first_success)

    if not success_time:
        return 0

    attempts_before_success = 0

    for failed_event in failed_events_by_ip[ip]:
        failed_time = parse_timestamp(failed_event)

        if failed_time and failed_time < success_time:
            attempts_before_success += 1

    return attempts_before_success


def calculate_severity(failed_attempts, accepted_attempts, attempts_before_success):
    score = 0
    reasons = []

    if failed_attempts >= 1:
        score += 2
        reasons.append("Failed SSH activity detected")

    if failed_attempts >= 5:
        score += 4
        reasons.append("5+ failed SSH attempts from same IP")

    if failed_attempts >= 10:
        score += 6
        reasons.append("10+ failed SSH attempts from same IP")

    if accepted_attempts >= 1:
        score += 1
        reasons.append("Successful SSH login detected")

    if attempts_before_success >= 1:
        score += 5
        reasons.append(
            f"Successful SSH login occurred after {attempts_before_success} failed attempt(s)"
        )

    if score >= 9:
        severity = "High"
    elif score >= 4:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity, reasons


def main():
    with open(INPUT_FILE, "r") as file:
        for line in file:
            if not line.strip():
                continue

            event = json.loads(line)
            event_type = event.get("event_type")
            source_ip = event.get("source_ip")
            username = event.get("username")

            if event_type not in ["failed_ssh_login", "accepted_ssh_login"]:
                continue

            all_ssh_events.append(event)

            if event_type == "failed_ssh_login":
                if source_ip:
                    failed_by_ip[source_ip] += 1
                    failed_events_by_ip[source_ip].append(event)

                if username:
                    failed_by_user[username] += 1

            elif event_type == "accepted_ssh_login":
                if source_ip:
                    accepted_by_ip[source_ip] += 1
                    accepted_events_by_ip[source_ip].append(event)

                if username:
                    accepted_by_user[username] += 1

    all_ips = set(failed_by_ip.keys()) | set(accepted_by_ip.keys())

    ssh_summary_by_ip = {}

    for ip in all_ips:
        attempts_before_success = calculate_attempts_before_success(ip)

        ssh_summary_by_ip[ip] = {
            "failed_attempts": failed_by_ip[ip],
            "accepted_attempts": accepted_by_ip[ip],
            "attempts_before_success": attempts_before_success,
            "successful_after_failures": attempts_before_success > 0,
            "failed_events": failed_events_by_ip[ip],
            "accepted_events": accepted_events_by_ip[ip]
        }

    with open(SSH_SUMMARY_FILE, "w") as summary_file:
        summary = {
            "finding": "ssh_activity_summary",
            "total_ssh_events": len(all_ssh_events),
            "total_failed_ssh_events": sum(failed_by_ip.values()),
            "total_accepted_ssh_events": sum(accepted_by_ip.values()),
            "failed_by_ip": dict(failed_by_ip),
            "accepted_by_ip": dict(accepted_by_ip),
            "failed_by_user": dict(failed_by_user),
            "accepted_by_user": dict(accepted_by_user),
            "ssh_summary_by_ip": ssh_summary_by_ip
        }

        summary_file.write(json.dumps(summary) + "\n")

    detections_found = False

    with open(OUTPUT_FILE, "w") as outfile:
        for ip in all_ips:
            failed_attempts = failed_by_ip[ip]
            accepted_attempts = accepted_by_ip[ip]
            attempts_before_success = calculate_attempts_before_success(ip)

            score, severity, reasons = calculate_severity(
                failed_attempts,
                accepted_attempts,
                attempts_before_success
            )

            if score >= 4:
                detections_found = True

                finding = {
                    "finding": "ssh_activity_detected",
                    "source_ip": ip,
                    "failed_attempts": failed_attempts,
                    "accepted_attempts": accepted_attempts,
                    "attempts_before_success": attempts_before_success,
                    "successful_after_failures": attempts_before_success > 0,
                    "severity": severity,
                    "severity_score": score,
                    "severity_reasons": reasons,
                    "failed_events": failed_events_by_ip[ip],
                    "accepted_events": accepted_events_by_ip[ip]
                }

                outfile.write(json.dumps(finding) + "\n")

        if not detections_found:
            outfile.write(json.dumps({
                "finding": "none",
                "message": "No suspicious SSH patterns were found.",
                "severity": "Low",
                "severity_score": 0,
                "severity_reasons": []
            }) + "\n")

    print(f"SSH summary written to {SSH_SUMMARY_FILE}")
    print(f"Suspicious SSH events written to {OUTPUT_FILE}")
    print(f"Total SSH events tracked: {len(all_ssh_events)}")


if __name__ == "__main__":
    main()