"""End-to-end analysis pipeline."""
from src.correlation_engine import correlate_events
from src.confidence_scorer import add_scores
from src.timeline_generator import build_timeline
from src.explanation_engine import explain_findings

def analyze(events):
    findings = add_scores(correlate_events(events))
    findings = explain_findings(findings)
    timeline = build_timeline(events, findings)
    return findings, timeline
