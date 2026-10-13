
import json
from pathlib import Path

import pandas as pd

from src.baselines import (
    independent_event_baseline,
    time_window_baseline,
)
from src.correlation_engine import correlate_logs
from src.evaluation import (
    calculate_metrics,
    findings_to_pairs,
    load_truth_pairs,
)
from src.experiments import run_ablation


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results"


def evaluate(name, expected, findings):
    metrics = calculate_metrics(
        expected,
        findings_to_pairs(findings),
    )
    metrics["method"] = name
    return metrics


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)

    all_metrics = []
    all_findings = []

    for split in ("development", "test"):
        event_path = DATA / f"{split}_events.csv"
        truth_path = DATA / f"{split}_ground_truth.csv"

        if not event_path.exists() or not truth_path.exists():
            raise FileNotFoundError(
                f"Missing dataset for {split}. "
                "Run python -m src.generate_data first."
            )

        expected = load_truth_pairs(truth_path)

        methods = {
            "full_framework": correlate_logs(event_path),
            "independent_event_baseline": independent_event_baseline(
                event_path
            ),
            "time_window_baseline": time_window_baseline(event_path),
            "ablation_without_R1": run_ablation(
                event_path, disabled_rules={"R1"}
            ),
            "ablation_without_R2": run_ablation(
                event_path, disabled_rules={"R2"}
            ),
            "ablation_without_R3": run_ablation(
                event_path, disabled_rules={"R3"}
            ),
            "ablation_without_maintenance_suppression": run_ablation(
                event_path, disable_maintenance=True
            ),
        }

        for method_name, findings in methods.items():
            metrics = evaluate(method_name, expected, findings)
            metrics["split"] = split
            all_metrics.append(metrics)

            for finding in findings:
                all_findings.append({
                    "split": split,
                    "method": method_name,
                    "rule_id": finding["rule_id"],
                    "event_ids": "|".join(finding["event_ids"]),
                    "reason": finding["reason"],
                    "confidence": finding["confidence"],
                })

    pd.DataFrame(all_metrics).to_csv(
        RESULTS / "metrics.csv",
        index=False,
    )

    pd.DataFrame(all_findings).to_csv(
        RESULTS / "findings.csv",
        index=False,
    )

    metadata = {
        "project": "PS-013",
        "evaluation_unit": "rule_id + sorted event ID group",
        "data_type": "synthetic",
        "note": (
            "Development and test use separate deterministic seeds, "
            "but share the same generator logic. This is not "
            "independent real-world validation."
        ),
    }

    (RESULTS / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print(pd.DataFrame(all_metrics).to_string(index=False))
    print(f"\nResults saved to: {RESULTS}")


if __name__ == "__main__":
    main()

