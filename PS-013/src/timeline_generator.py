"""Timeline construction from event IDs cited by findings."""
def build_timeline(events, findings):
    ids = {event_id for finding in findings for event_id in finding["event_ids"]}
    timeline = events[events["event_id"].isin(ids)].copy()
    timeline["related_findings"] = timeline["event_id"].apply(
        lambda event_id: ", ".join(f["finding_id"] for f in findings if event_id in f["event_ids"])
    )
    return timeline.sort_values(["timestamp", "event_id"]).reset_index(drop=True)
