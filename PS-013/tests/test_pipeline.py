
import pandas as pd
import pytest

from src.log_parser import parse_logs
from src.correlation_engine import correlate_logs
from src.evaluation import calculate_metrics, findings_to_pairs


def sample_logs():
    return pd.DataFrame([
        {
            "event_id": "E1",
            "timestamp": "2026-09-01T09:00:00Z",
            "user": "alice",
            "host": "WS-01",
            "event_type": "failed_login",
        },
        {
            "event_id": "E2",
            "timestamp": "2026-09-01T09:02:00Z",
            "user": "alice",
            "host": "WS-01",
            "event_type": "failed_login",
        },
        {
            "event_id": "E3",
            "timestamp": "2026-09-01T09:04:00Z",
            "user": "alice",
            "host": "WS-01",
            "event_type": "failed_login",
        },
        {
            "event_id": "E4",
            "timestamp": "2026-09-01T10:00:00Z",
            "user": "bob",
            "host": "WS-02",
            "event_type": "successful_login",
        },
        {
            "event_id": "E5",
            "timestamp": "2026-09-01T10:05:00Z",
            "user": "bob",
            "host": "WS-02",
            "event_type": "powershell_execution",
        },
    ])


def test_parser_supports_missing_optional_column():
    parsed = parse_logs(sample_logs())
    assert "maintenance_approved" in parsed.columns
    assert not parsed["maintenance_approved"].any()


def test_detects_repeated_failed_logins():
    findings = correlate_logs(sample_logs())
    assert any(
        item["rule_id"] == "R1"
        and set(item["event_ids"]) == {"E1", "E2", "E3"}
        for item in findings
    )


def test_detects_login_followed_by_powershell():
    findings = correlate_logs(sample_logs())
    assert any(
        item["rule_id"] == "R2"
        and set(item["event_ids"]) == {"E4", "E5"}
        for item in findings
    )


def test_metrics_are_bounded():
    metrics = calculate_metrics(
        {("R1", ("E1", "E2"))},
        {("R1", ("E1", "E2"))},
    )
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0


def test_duplicate_event_ids_are_rejected():
    data = sample_logs()
    data.loc[1, "event_id"] = "E1"

    with pytest.raises(ValueError, match="Duplicate"):
        parse_logs(data)


def test_approved_maintenance_does_not_suppress_download():
    data = pd.DataFrame([
        {
            "event_id": "E10",
            "timestamp": "2026-09-01T12:00:00Z",
            "user": "dave",
            "host": "WS-04",
            "event_type": "successful_login",
            "maintenance_approved": True,
        },
        {
            "event_id": "E11",
            "timestamp": "2026-09-01T12:05:00Z",
            "user": "dave",
            "host": "WS-04",
            "event_type": "suspicious_download",
            "maintenance_approved": True,
        },
    ])

    findings = correlate_logs(data)

    assert any(
        item["rule_id"] == "R2"
        and set(item["event_ids"]) == {"E10", "E11"}
        for item in findings
    )

