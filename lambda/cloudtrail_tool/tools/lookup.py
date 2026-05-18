from __future__ import annotations

import datetime

import boto3

from .._guardrails import MAX_LOOKBACK_DAYS, MAX_RESULTS, clamp_lookback_days, clamp_result_count
from .._mcp import error, success

cloudtrail = boto3.client("cloudtrail")


def _lookup_events(attributes: list[dict], lookback_days: int, max_results: int) -> list[dict]:
    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = end_time - datetime.timedelta(days=lookback_days)

    events: list[dict] = []
    kwargs: dict = {
        "LookupAttributes": attributes,
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": min(max_results, 50),
    }

    while len(events) < max_results:
        resp = cloudtrail.lookup_events(**kwargs)
        events.extend(resp.get("Events", []))
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
        kwargs["MaxResults"] = min(max_results - len(events), 50)

    return events[:max_results]


def lookup_by_user(event: dict) -> dict:
    username = event.get("username")
    if not username:
        return error("Missing required parameter: username")

    lookback_days = clamp_lookback_days(event.get("lookback_days", MAX_LOOKBACK_DAYS))
    max_results = clamp_result_count(event.get("max_results", MAX_RESULTS))

    events = _lookup_events(
        [{"AttributeKey": "Username", "AttributeValue": username}],
        lookback_days,
        max_results,
    )
    return success({"events": events, "count": len(events), "lookback_days": lookback_days, "refused": None})


def lookup_by_resource(event: dict) -> dict:
    resource_name = event.get("resource_name")
    if not resource_name:
        return error("Missing required parameter: resource_name")

    lookback_days = clamp_lookback_days(event.get("lookback_days", MAX_LOOKBACK_DAYS))
    max_results = clamp_result_count(event.get("max_results", MAX_RESULTS))

    events = _lookup_events(
        [{"AttributeKey": "ResourceName", "AttributeValue": resource_name}],
        lookback_days,
        max_results,
    )
    return success({"events": events, "count": len(events), "lookback_days": lookback_days, "refused": None})


def lookup_by_event_name(event: dict) -> dict:
    event_name = event.get("event_name")
    if not event_name:
        return error("Missing required parameter: event_name")

    lookback_days = clamp_lookback_days(event.get("lookback_days", MAX_LOOKBACK_DAYS))
    max_results = clamp_result_count(event.get("max_results", MAX_RESULTS))

    events = _lookup_events(
        [{"AttributeKey": "EventName", "AttributeValue": event_name}],
        lookback_days,
        max_results,
    )
    return success({"events": events, "count": len(events), "lookback_days": lookback_days, "refused": None})


def investigate_event(event: dict) -> dict:
    event_id = event.get("event_id")
    if not event_id:
        return error("Missing required parameter: event_id")

    lookback_days = clamp_lookback_days(event.get("lookback_days", MAX_LOOKBACK_DAYS))

    events = _lookup_events(
        [{"AttributeKey": "EventId", "AttributeValue": event_id}],
        lookback_days,
        1,
    )

    if not events:
        return error(f"Event {event_id} not found")

    return success({"events": events, "count": 1, "lookback_days": lookback_days, "refused": None})


TOOLS = {
    "lookup_by_user": lookup_by_user,
    "lookup_by_resource": lookup_by_resource,
    "lookup_by_event_name": lookup_by_event_name,
    "investigate_event": investigate_event,
}
