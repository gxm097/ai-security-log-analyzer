import json
from collections import Counter, defaultdict

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


def calculate_severity(failed_attempts, accepted_attempts):
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

    if accepted_attempts >= 1 and failed_attempts >= 1:
        score += 5
        reasons.append("Successful SSH login after failed attempts from same IP")

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
            "all_ssh_events": all_ssh_events
        }

        summary_file.write(json.dumps(summary) + "\n")

    detections_found = False

    with open(OUTPUT_FILE, "w") as outfile:
        all_ips = set(failed_by_ip.keys()) | set(accepted_by_ip.keys())

        for ip in all_ips:
            failed_attempts = failed_by_ip[ip]
            accepted_attempts = accepted_by_ip[ip]

            score, severity, reasons = calculate_severity(
                failed_attempts,
                accepted_attempts
            )

            if score >= 4:
                detections_found = True

                finding = {
                    "finding": "ssh_activity_detected",
                    "source_ip": ip,
                    "failed_attempts": failed_attempts,
                    "accepted_attempts": accepted_attempts,
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