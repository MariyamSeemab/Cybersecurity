
import pandas as pd


def load_truth_pairs(source):
    df = pd.read_csv(source)

    required = {"rule_id", "event_ids"}
    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"Ground truth missing columns: {sorted(missing)}"
        )

    pairs = set()

    for _, row in df.iterrows():
        raw_ids = str(row["event_ids"]).replace(";", "|")

        event_ids = [
            value.strip()
            for value in raw_ids.split("|")
            if value.strip()
        ]

        pairs.add((
            str(row["rule_id"]).strip(),
            tuple(sorted(set(event_ids))),
        ))

    return pairs


def findings_to_pairs(findings):
    return {
        (
            str(item["rule_id"]),
            tuple(sorted(set(item["event_ids"]))),
        )
        for item in findings
    }


def calculate_metrics(expected, predicted):
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "expected": len(expected),
        "predicted": len(predicted),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }
