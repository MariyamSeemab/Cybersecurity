"""Transparent, deterministic event-correlation rules for the PS-013 prototype."""
from datetime import timedelta

def _same_identity(a, b):
    same_user = bool(a["user"]) and a["user"] == b["user"]
    same_host = bool(a["host"]) and a["host"] == b["host"]
    return same_user and same_host

def correlate_events(events, failed_login_threshold=3, auth_window_minutes=10,
                     post_login_window_minutes=30):
    """Return findings with traceable event IDs; does not assert that an attack occurred."""
    rows = events.to_dict("records")
    findings = []

    # R1: repeated failed logins followed by a success for the same user/host.
    for success in [r for r in rows if r["event_type"] == "successful_login"]:
        start = success["timestamp"] - timedelta(minutes=auth_window_minutes)
        failures = [
            r for r in rows
            if r["event_type"] == "failed_login"
            and r["timestamp"] <= success["timestamp"]
            and r["timestamp"] >= start
            and _same_identity(r, success)
        ]
        if len(failures) >= failed_login_threshold:
            evidence = failures + [success]
            findings.append({
                "finding_id": f"F{len(findings)+1:03d}",
                "rule_id": "R1",
                "title": "Repeated authentication failures followed by success",
                "severity": "medium",
                "event_ids": [r["event_id"] for r in evidence],
                "start_time": min(r["timestamp"] for r in evidence),
                "end_time": success["timestamp"],
                "explanation": (
                    f"{len(failures)} failed login event(s) were followed by a successful "
                    f"login for the same user and host within {auth_window_minutes} minutes. "
                    "This can indicate credential guessing, but may also have a benign cause."
                ),
                "evidence_completeness": min(1.0, len(failures) / max(failed_login_threshold, 1)),
                "temporal_consistency": 1.0,
                "identity_consistency": 1.0,
            })

    # R2: a successful login followed by PowerShell or suspicious download.
    for login in [r for r in rows if r["event_type"] == "successful_login"]:
        end = login["timestamp"] + timedelta(minutes=post_login_window_minutes)
        related = [
            r for r in rows
            if r["timestamp"] >= login["timestamp"] and r["timestamp"] <= end
            and _same_identity(r, login)
            and r["event_type"] in {"powershell_execution", "suspicious_download"}
        ]
        if related:
            evidence = [login] + related
            findings.append({
                "finding_id": f"F{len(findings)+1:03d}",
                "rule_id": "R2",
                "title": "Suspicious activity following successful login",
                "severity": "high" if any(r["event_type"] == "suspicious_download" for r in related) else "medium",
                "event_ids": [r["event_id"] for r in evidence],
                "start_time": login["timestamp"],
                "end_time": max(r["timestamp"] for r in related),
                "explanation": (
                    f"A successful login was followed by {', '.join(r['event_type'] for r in related)} "
                    f"on the same user and host within {post_login_window_minutes} minutes. "
                    "Validate process command lines and network context before drawing conclusions."
                ),
                "evidence_completeness": min(1.0, len(related) / 2),
                "temporal_consistency": 1.0,
                "identity_consistency": 1.0,
            })

    # R3: PowerShell execution followed by administrator account creation.
    for execution in [r for r in rows if r["event_type"] == "powershell_execution"]:
        end = execution["timestamp"] + timedelta(minutes=post_login_window_minutes)
        accounts = [
            r for r in rows
            if r["event_type"] == "admin_account_created"
            and execution["timestamp"] <= r["timestamp"] <= end
            and _same_identity(r, execution)
        ]
        if accounts:
            for account in accounts:
                findings.append({
                    "finding_id": f"F{len(findings)+1:03d}",
                    "rule_id": "R3",
                    "title": "Execution followed by administrator account creation",
                    "severity": "high",
                    "event_ids": [execution["event_id"], account["event_id"]],
                    "start_time": execution["timestamp"],
                    "end_time": account["timestamp"],
                    "explanation": (
                        "PowerShell execution was followed by administrator-account creation "
                        "for the same user and host within the configured time window. This is "
                        "a potential privilege-escalation sequence and requires investigation."
                    ),
                    "evidence_completeness": 1.0,
                    "temporal_consistency": 1.0,
                    "identity_consistency": 1.0,
                })
    return findings
