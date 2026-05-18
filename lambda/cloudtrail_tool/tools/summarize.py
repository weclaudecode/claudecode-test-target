from __future__ import annotations

import datetime
from collections import Counter

import boto3

from .._guardrails import MAX_LOOKBACK_DAYS, MAX_RESULTS, clamp_lookback_days
from .._mcp import error, success

cloudtrail = boto3.client("cloudtrail")

_GROUP_BY_FIELDS = {
    "username": "Username",
    "eventName": "EventName",
    "eventSource": "EventSource",
}


def summarize_window(event: dict) -> dict:
    lookback_days = clamp_lookback_days(event.get("lookback_days", MAX_LOOKBACK_DAYS))
    group_by = event.get("group_by", "eventName")

    if group_by not in _GROUP_BY_FIELDS:
        return error(f"Invalid group_by '{group_by}': must be one of {list(_GROUP_BY_FIELDS)}")

    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = end_time - datetime.timedelta(days=lookback_days)

    events: list[dict] = []
    kwargs: dict = {"StartTime": start_time, "EndTime": end_time, "MaxResults": 50}

    while len(events) < MAX_RESULTS:
        resp = cloudtrail.lookup_events(**kwargs)
        events.extend(resp.get("Events", []))
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
        kwargs["MaxResults"] = min(MAX_RESULTS - len(events), 50)

    field = _GROUP_BY_FIELDS[group_by]
    counts: Counter = Counter(e.get(field, "unknown") for e in events)
    top20 = [{"key": k, "count": v} for k, v in counts.most_common(20)]

    return success({
        "summary": top20,
        "total_events": len(events),
        "lookback_days": lookback_days,
        "group_by": group_by,
    })


TOOLS = {"summarize_window": summarize_window}
