import argparse
from pathlib import Path
from src.log_parser import load_events
from src.pipeline import analyze
from src.report_generator import write_html_report

def main():
    parser = argparse.ArgumentParser(description="Run PS-013 analysis on a CSV log file.")
    parser.add_argument("--input", default="data/raw_logs.csv")
    parser.add_argument("--output", default="reports")
    args = parser.parse_args()
    events = load_events(args.input)
    findings, timeline = analyze(events)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    timeline.to_csv(out / "timeline.csv", index=False)
    write_html_report(findings, timeline, out / "investigation_report.html")
    print(f"Loaded {len(events)} events; produced {len(findings)} findings.")
    print(f"Report: {out / 'investigation_report.html'}")
if __name__ == "__main__":
    main()
