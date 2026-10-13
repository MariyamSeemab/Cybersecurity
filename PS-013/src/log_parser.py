
from pathlib import Path

import pandas as pd


REQUIRED_COLUMNS = {
    "event_id",
    "timestamp",
    "user",
    "host",
    "event_type",
}

OPTIONAL_DEFAULTS = {
    "maintenance_approved": False,
}


def parse_logs(source):
    """Load and validate cybersecurity event logs."""
    if isinstance(source, pd.DataFrame):
        df = source.copy()
    else:
        df = pd.read_csv(Path(source))

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    for column, default in OPTIONAL_DEFAULTS.items():
        if column not in df.columns:
            df[column] = default

    if df["event_id"].isna().any():
        raise ValueError("event_id cannot be empty")

    df["event_id"] = df["event_id"].astype(str).str.strip()

    if (df["event_id"] == "").any():
        raise ValueError("event_id cannot be empty")

    if df["event_id"].duplicated().any():
        duplicates = df.loc[
            df["event_id"].duplicated(),
            "event_id",
        ].tolist()
        raise ValueError(f"Duplicate event IDs: {duplicates}")

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True,
    )

    if df["timestamp"].isna().any():
        raise ValueError("Invalid or missing timestamps")

    for column in ("user", "host", "event_type"):
        df[column] = df[column].fillna("").astype(str).str.strip()

    if (df["event_type"] == "").any():
        raise ValueError("event_type cannot be empty")

    if df["maintenance_approved"].dtype == bool:
        pass
    else:
        normalized = (
            df["maintenance_approved"]
            .astype(str)
            .str.strip()
            .str.lower()
        )

        mapping = {
            "true": True,
            "1": True,
            "yes": True,
            "false": False,
            "0": False,
            "no": False,
            "": False,
            "nan": False,
            "none": False,
        }

        invalid = ~normalized.isin(mapping)

        if invalid.any():
            values = normalized[invalid].unique().tolist()
            raise ValueError(
                f"Invalid maintenance_approved values: {values}"
            )

        df["maintenance_approved"] = normalized.map(mapping)

    return df.sort_values(
        ["timestamp", "event_id"]
    ).reset_index(drop=True)

