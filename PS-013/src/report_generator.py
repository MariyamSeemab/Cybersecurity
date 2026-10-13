"""Write a self-contained HTML report from analysis results."""
from html import escape
from pathlib import Path

def write_html_report(findings, timeline, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cards = []
    for f in findings:
        ids = ", ".join(f.get("event_ids", []))
        cards.append(
            "<section class='finding'>"
            f"<h2>{escape(f.get('title','Finding'))}</h2>"
            f"<p><b>Rule:</b> {escape(f.get('rule_id',''))} | "
            f"<b>Severity:</b> {escape(f.get('severity',''))} | "
            f"<b>Evidence strength:</b> {escape(str(f.get('evidence_strength_score','N/A')))} / 100</p>"
            f"<p>{escape(f.get('explanation',''))}</p>"
            f"<p><b>Evidence event IDs:</b> {escape(ids or 'None')}</p>"
            "</section>"
        )
    table = timeline.to_html(index=False, escape=True, classes="timeline") if not timeline.empty else "<p>No correlated events.</p>"
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>PS-013 Investigation Report</title>
<style>body{{font-family:Arial,sans-serif;max-width:1100px;margin:32px auto;padding:0 18px;color:#202733}}
.notice{{background:#fff4d6;padding:12px;border-left:4px solid #bd8b16}}
.finding{{border:1px solid #d8dee8;border-radius:8px;padding:14px;margin:14px 0}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #d8dee8;padding:7px;text-align:left}}
th{{background:#f0f3f8}}h1{{margin-bottom:4px}}</style></head><body>
<h1>PS-013 Investigation Report</h1><p>Explainable Incident Reconstruction and Evidence Correlation Framework</p>
<div class="notice"><b>Research prototype notice:</b> Findings are rule-based investigative leads, not proof of compromise.
Scores are heuristic evidence-strength indicators, not probabilities. Validate against source logs.</div>
<h2>Findings</h2>{''.join(cards) if cards else '<p>No findings.</p>'}
<h2>Reconstructed timeline</h2>{table}
</body></html>"""
    output_path.write_text(html, encoding="utf-8")
    return output_path
