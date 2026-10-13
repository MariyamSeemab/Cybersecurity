
from src.log_parser import parse_logs
from src.correlation_engine import correlate_logs


def run_ablation(source, disabled_rules=None, disable_maintenance=False):
    """
    Run the detector with selected rules removed.

    disable_maintenance=True removes the approved-maintenance
    suppression by clearing the flag before detection.
    """
    df = parse_logs(source)

    if disable_maintenance:
        df["maintenance_approved"] = False

    findings = correlate_logs(df)
    disabled_rules = set(disabled_rules or [])

    return [
        finding
        for finding in findings
        if finding["rule_id"] not in disabled_rules
    ]

