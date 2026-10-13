
from src.log_parser import parse_logs


FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 10
FOLLOW_UP_WINDOW_MINUTES = 30


def correlate_logs(source):
    df = parse_logs(source)
    findings = []

    def add_finding(rule_id, event_ids, reason, confidence):
        findings.append({
            "rule_id": rule_id,
            "event_ids": sorted(set(event_ids)),
            "reason": reason,
            "confidence": confidence,
        })

    # R1: Repeated failed logins.
    failed = df[df["event_type"] == "failed_login"]

    for (user, host), group in failed.groupby(["user", "host"]):
        group = group.sort_values("timestamp").reset_index(drop=True)

        for start in range(len(group)):
            first_time = group.loc[start, "timestamp"]
            end_time = first_time + __import__("pandas").Timedelta(
                minutes=FAILED_LOGIN_WINDOW_MINUTES
            )

            window = group[
                (group["timestamp"] >= first_time)
                & (group["timestamp"] <= end_time)
            ]

            if len(window) >= FAILED_LOGIN_THRESHOLD:
                ids = window["event_id"].tolist()
                add_finding(
                    "R1",
                    ids,
                    (
                        f"{len(window)} failed logins for user "
                        f"{user} on host {host} within "
                        f"{FAILED_LOGIN_WINDOW_MINUTES} minutes."
                    ),
                    0.90,
                )
                break

    # R2: Successful login followed by PowerShell activity
    # or a suspicious download.
    for _, login in df[
        df["event_type"] == "successful_login"
    ].iterrows():
        end_time = login["timestamp"] + __import__("pandas").Timedelta(
            minutes=FOLLOW_UP_WINDOW_MINUTES
        )

        followups = df[
            (df["user"] == login["user"])
            & (df["host"] == login["host"])
            & (df["timestamp"] > login["timestamp"])
            & (df["timestamp"] <= end_time)
            & (
                df["event_type"].isin(
                    ["powershell_execution", "suspicious_download"]
                )
            )
        ]

        for _, activity in followups.iterrows():
            # Approved maintenance can suppress routine PowerShell
            # correlation, but never a suspicious download.
            is_download = (
                activity["event_type"] == "suspicious_download"
            )

            both_approved = (
                bool(login["maintenance_approved"])
                and bool(activity["maintenance_approved"])
            )

            if both_approved and not is_download:
                continue

            add_finding(
                "R2",
                [login["event_id"], activity["event_id"]],
                (
                    f"Successful login followed by "
                    f"{activity['event_type']} for user "
                    f"{login['user']} on host {login['host']} "
                    f"within {FOLLOW_UP_WINDOW_MINUTES} minutes."
                ),
                0.85 if is_download else 0.80,
            )

    # R3: Suspicious downloads are independently detectable.
    downloads = df[
        df["event_type"] == "suspicious_download"
    ]

    for _, event in downloads.iterrows():
        add_finding(
            "R3",
            [event["event_id"]],
            (
                f"Suspicious download detected for user "
                f"{event['user']} on host {event['host']}."
            ),
            0.95,
        )

    # Remove exact duplicate rule/evidence combinations.
    unique = {}
    for finding in findings:
        key = (
            finding["rule_id"],
            tuple(finding["event_ids"]),
        )
        unique[key] = finding

    return list(unique.values())

