"""Convert structured findings into human-readable investigation notes."""
def explain_findings(findings):
    if not findings:
        return [{
            "title": "No configured correlation rules matched",
            "explanation": (
                "No finding was produced by the current rules. This does not prove that the "
                "logs are benign; the activity may be outside the prototype's rule coverage."
            ),
            "event_ids": [],
            "rule_id": "NONE",
            "severity": "informational",
            "evidence_strength_score": 0.0,
        }]
    return findings
