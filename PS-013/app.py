import streamlit as st
import plotly.express as px
from src.log_parser import load_events
from src.pipeline import analyze
from src.report_generator import write_html_report
from pathlib import Path
import tempfile

st.set_page_config(page_title="PS-013 Incident Reconstruction", page_icon="🛡️", layout="wide")
st.title("PS-013 | Explainable Incident Reconstruction")
st.caption("Rule-based research prototype • Findings are investigative leads, not proof of compromise.")

uploaded = st.file_uploader("Upload security logs (CSV)", type=["csv"])
if uploaded is None:
    st.info("Upload a CSV or use the included sample dataset.")
    input_source = "data/raw_logs.csv"
else:
    input_source = uploaded

try:
    events = load_events(input_source)
    findings, timeline = analyze(events)
    c1, c2, c3 = st.columns(3)
    c1.metric("Events loaded", len(events))
    c2.metric("Findings", len(findings))
    c3.metric("Events in reconstructed timeline", len(timeline))
    st.subheader("Correlated findings")
    if findings:
        for f in findings:
            with st.expander(f"{f['finding_id']} · {f['title']} · {f['severity'].upper()}"):
                st.write(f["explanation"])
                st.write("Evidence event IDs:", ", ".join(f["event_ids"]))
                st.metric("Evidence-strength score (not probability)", f"{f['evidence_strength_score']}/100")
                st.caption(f"Rule {f['rule_id']} · {f['score_interpretation']}")
    else:
        st.success("No configured rules matched. This does not prove the logs are benign.")
    st.subheader("Reconstructed timeline")
    if not timeline.empty:
        plot = px.scatter(timeline, x="timestamp", y="event_type", color="event_type",
                          hover_data=["event_id", "user", "host", "details", "related_findings"])
        st.plotly_chart(plot, use_container_width=True)
        st.dataframe(timeline, use_container_width=True)
    else:
        st.write("No correlated events to display.")
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "investigation_report.html"
        write_html_report(findings, timeline, report_path)
        st.download_button("Download HTML investigation report", report_path.read_bytes(),
                           file_name="ps013_investigation_report.html", mime="text/html")
except Exception as exc:
    st.error(f"Could not analyze the file: {exc}")
