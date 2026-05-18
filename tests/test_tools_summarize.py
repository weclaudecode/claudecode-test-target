from __future__ import annotations

import datetime
import json
from unittest.mock import patch

import boto3
import moto
import pytest

import cloudtrail_tool.tools.summarize as summarize_module
from cloudtrail_tool._guardrails import MAX_LOOKBACK_DAYS
from cloudtrail_tool.tools.summarize import summarize_window


def _make_events(n: int, event_name: str = "AssumeRole", username: str = "alice") -> list[dict]:
    return [
        {
            "EventId": f"evt-{i:03d}",
            "EventName": event_name,
            "Username": username,
            "EventSource": "sts.amazonaws.com",
            "EventTime": datetime.datetime(2026, 5, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
        }
        for i in range(n)
    ]


@pytest.fixture
def patched_client(monkeypatch, aws_credentials):
    with moto.mock_aws():
        client = boto3.client("cloudtrail", region_name="us-east-1")
        monkeypatch.setattr(summarize_module, "cloudtrail", client)
        yield client


def test_summarize_window_happy_path(patched_client):
    events = _make_events(3, "AssumeRole") + _make_events(2, "ListBuckets")
    with patch.object(patched_client, "lookup_events", return_value={"Events": events}):
        result = summarize_window({})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["total_events"] == 5
    assert data["group_by"] == "eventName"
    top = {entry["key"]: entry["count"] for entry in data["summary"]}
    assert top["AssumeRole"] == 3
    assert top["ListBuckets"] == 2


def test_summarize_window_group_by_username(patched_client):
    events = _make_events(2, username="alice") + _make_events(3, username="bob")
    with patch.object(patched_client, "lookup_events", return_value={"Events": events}):
        result = summarize_window({"group_by": "username"})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    top = {entry["key"]: entry["count"] for entry in data["summary"]}
    assert top["bob"] == 3
    assert top["alice"] == 2


def test_summarize_window_lookback_clamped(patched_client):
    with patch.object(patched_client, "lookup_events", return_value={"Events": []}):
        result = summarize_window({"lookback_days": 999})

    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"])["lookback_days"] == MAX_LOOKBACK_DAYS


def test_summarize_window_invalid_group_by(patched_client):
    result = summarize_window({"group_by": "invalid_field"})
    assert result["isError"] is True
    assert "group_by" in json.loads(result["content"][0]["text"])["error"]


def test_summarize_window_group_by_event_source(patched_client):
    events = [
        {**e, "EventSource": "s3.amazonaws.com"}
        for e in _make_events(2, "ListBuckets")
    ] + [
        {**e, "EventSource": "sts.amazonaws.com"}
        for e in _make_events(4, "AssumeRole")
    ]
    with patch.object(patched_client, "lookup_events", return_value={"Events": events}):
        result = summarize_window({"group_by": "eventSource"})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    top = {entry["key"]: entry["count"] for entry in data["summary"]}
    assert top["sts.amazonaws.com"] == 4
    assert top["s3.amazonaws.com"] == 2
