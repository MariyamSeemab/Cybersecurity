
from src.log_parser import parse_logs
from src.evaluation import findings_to_pairs


def independent_event_baseline(source):
    """Match suspicious event types without temporal correlation."""
    df = parse_logs(source)
    findings = []

    for _, event in df.iterrows():
        event_type = event["event_type"]

        if event_type == "suspicious_download":
            rule_id = "R3"
        elif event_type == "failed_login":
            rule_id = "R1"
        elif event_type == "powershell_execution":
            rule_id = "R2"
        else:
            continue

        findings.append({
            "rule_id": rule_id,
            "event_ids": [event["event_id"]],
            "reason": (
                f"Baseline matched event type {event_type}."
            ),
            "confidence": 0.50,
        })

    return findings


def time_window_baseline(source):
    """R2 baseline: login and follow-up activity within 30 minutes."""
    df = parse_logs(source)
    findings = []

    logins = df[df["event_type"] == "successful_login"]
    activities = df[
        df["event_type"].isin(
            ["powershell_execution", "suspicious_download"]
        )
    ]

    for _, login in logins.iterrows():
        matches = activities[
            (activities["user"] == login["user"])
            & (activities["host"] == login["host"])
            & (activities["timestamp"] > login["timestamp"])
            & (
                activities["timestamp"]
                <= login["timestamp"]
                + __import__("pandas").Timedelta(minutes=30)
            )
        ]

        for _, activity in matches.iterrows():
            findings.append({
                "rule_id": "R2",
                "event_ids": [
                    login["event_id"],
                    activity["event_id"],
                ],
                "reason": "Baseline time-window correlation.",
                "confidence": 0.50,
            })

    return findings

