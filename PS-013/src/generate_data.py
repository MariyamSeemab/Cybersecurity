
from pathlib import Path
import random

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def generate_split(prefix, seed, scenarios=50):
    rng = random.Random(seed)
    events = []
    truth = []
    counter = 1

    def add(ts, user, host, event_type, approved=False):
        nonlocal counter
        event_id = f"{prefix}{counter:04d}"
        counter += 1

        events.append({
            "event_id": event_id,
            "timestamp": ts,
            "user": user,
            "host": host,
            "event_type": event_type,
            "maintenance_approved": approved,
        })
        return event_id

    base = pd.Timestamp("2026-01-01T00:00:00Z")

    for i in range(scenarios):
        ts = base + pd.Timedelta(minutes=i * 120)
        user = f"user_{i:03d}"
        host = f"host_{i:03d}"

        kind = i % 4

        if kind == 0:
            ids = [
                add(ts, user, host, "failed_login"),
                add(ts + pd.Timedelta(minutes=2), user, host, "failed_login"),
                add(ts + pd.Timedelta(minutes=4), user, host, "failed_login"),
            ]
            truth.append({"rule_id": "R1", "event_ids": "|".join(ids)})

        elif kind == 1:
            login = add(ts, user, host, "successful_login")
            activity = add(
                ts + pd.Timedelta(minutes=5),
                user,
                host,
                "powershell_execution",
            )
            truth.append({
                "rule_id": "R2",
                "event_ids": f"{login}|{activity}",
            })

        elif kind == 2:
            event_id = add(ts, user, host, "suspicious_download")
            truth.append({"rule_id": "R3", "event_ids": event_id})

        else:
            # Benign approved maintenance, expected not to trigger R2.
            add(ts, user, host, "successful_login", approved=True)
            add(
                ts + pd.Timedelta(minutes=5),
                user,
                host,
                "powershell_execution",
                approved=True,
            )

        # Add background noise.
        if rng.random() < 0.5:
            add(
                ts + pd.Timedelta(minutes=45),
                f"noise_{i}",
                host,
                "normal_activity",
            )

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(events).to_csv(
        DATA_DIR / f"{prefix.lower()}_events.csv",
        index=False,
    )
    pd.DataFrame(truth).to_csv(
        DATA_DIR / f"{prefix.lower()}_ground_truth.csv",
        index=False,
    )


if __name__ == "__main__":
    generate_split("development", seed=202610)
    generate_split("test", seed=88421)
    print("Synthetic development and test datasets generated.")

