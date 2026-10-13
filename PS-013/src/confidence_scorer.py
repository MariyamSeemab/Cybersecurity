"""Heuristic evidence-strength scoring; not a probability of compromise."""
def score_finding(finding):
    weights = {"evidence_completeness": 0.50, "temporal_consistency": 0.25, "identity_consistency": 0.25}
    score = sum(float(finding.get(k, 0.0)) * w for k, w in weights.items()) * 100
    return round(max(0.0, min(100.0, score)), 1)

def add_scores(findings):
    for finding in findings:
        finding["evidence_strength_score"] = score_finding(finding)
        finding["score_interpretation"] = (
            "Heuristic evidence-strength score; not a calibrated probability."
        )
    return findings
