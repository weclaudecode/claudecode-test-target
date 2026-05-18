from __future__ import annotations

import datetime
import json
from unittest.mock import patch

import boto3
import moto
import pytest

import cloudtrail_tool.tools.lookup as lookup_module
from cloudtrail_tool._guardrails import MAX_LOOKBACK_DAYS
from cloudtrail_tool.tools.lookup import (
    investigate_event,
    lookup_by_event_name,
    lookup_by_resource,
    lookup_by_user,
)


def _make_ct_event(
    event_id: str = "evt-001",
    username: str = "alice",
    event_name: str = "AssumeRole",
    event_source: str = "sts.amazonaws.com",
) -> dict:
    return {
        "EventId": event_id,
        "EventName": event_name,
        "Username": username,
        "EventSource": event_source,
        "EventTime": datetime.datetime(2026, 5, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
        "CloudTrailEvent": f'{{"eventVersion": "1.08", "eventName": "{event_name}"}}',
    }


@pytest.fixture
def patched_client(monkeypatch, aws_credentials):
    with moto.mock_aws():
        client = boto3.client("cloudtrail", region_name="us-east-1")
        monkeypatch.setattr(lookup_module, "cloudtrail", client)
        yield client


# --- lookup_by_user ---

def test_lookup_by_user_happy_path(patched_client):
    evt = _make_ct_event(username="alice")
    with patch.object(patched_client, "lookup_events", return_value={"Events": [evt]}) as mock_le:
        result = lookup_by_user({"username": "alice"})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["count"] == 1
    assert data["refused"] is None
    assert data["lookback_days"] == MAX_LOOKBACK_DAYS
    call_kwargs = mock_le.call_args.kwargs
    assert call_kwargs["LookupAttributes"] == [{"AttributeKey": "Username", "AttributeValue": "alice"}]


def test_lookup_by_user_missing_param(patched_client):
    result = lookup_by_user({})
    assert result["isError"] is True
    assert "username" in json.loads(result["content"][0]["text"])["error"]


def test_lookup_by_user_lookback_clamped(patched_client):
    with patch.object(patched_client, "lookup_events", return_value={"Events": []}):
        result = lookup_by_user({"username": "alice", "lookback_days": 999})

    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"])["lookback_days"] == MAX_LOOKBACK_DAYS


# --- lookup_by_resource ---

def test_lookup_by_resource_happy_path(patched_client):
    evt = _make_ct_event()
    with patch.object(patched_client, "lookup_events", return_value={"Events": [evt]}) as mock_le:
        result = lookup_by_resource({"resource_name": "my-role"})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["count"] == 1
    assert mock_le.call_args.kwargs["LookupAttributes"] == [
        {"AttributeKey": "ResourceName", "AttributeValue": "my-role"}
    ]


def test_lookup_by_resource_missing_param(patched_client):
    result = lookup_by_resource({})
    assert result["isError"] is True
    assert "resource_name" in json.loads(result["content"][0]["text"])["error"]


def test_lookup_by_resource_lookback_clamped(patched_client):
    with patch.object(patched_client, "lookup_events", return_value={"Events": []}):
        result = lookup_by_resource({"resource_name": "my-role", "lookback_days": 100})
    assert json.loads(result["content"][0]["text"])["lookback_days"] == MAX_LOOKBACK_DAYS


# --- lookup_by_event_name ---

def test_lookup_by_event_name_happy_path(patched_client):
    evt = _make_ct_event(event_name="ListBuckets")
    with patch.object(patched_client, "lookup_events", return_value={"Events": [evt]}) as mock_le:
        result = lookup_by_event_name({"event_name": "ListBuckets"})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["count"] == 1
    assert mock_le.call_args.kwargs["LookupAttributes"] == [
        {"AttributeKey": "EventName", "AttributeValue": "ListBuckets"}
    ]


def test_lookup_by_event_name_missing_param(patched_client):
    result = lookup_by_event_name({})
    assert result["isError"] is True
    assert "event_name" in json.loads(result["content"][0]["text"])["error"]


def test_lookup_by_event_name_lookback_clamped(patched_client):
    with patch.object(patched_client, "lookup_events", return_value={"Events": []}):
        result = lookup_by_event_name({"event_name": "ListBuckets", "lookback_days": 30})
    assert json.loads(result["content"][0]["text"])["lookback_days"] == MAX_LOOKBACK_DAYS


# --- investigate_event ---

def test_investigate_event_happy_path(patched_client):
    evt = _make_ct_event(event_id="evt-abc-123")
    with patch.object(patched_client, "lookup_events", return_value={"Events": [evt]}) as mock_le:
        result = investigate_event({"event_id": "evt-abc-123"})

    assert result["isError"] is False
    data = json.loads(result["content"][0]["text"])
    assert data["count"] == 1
    assert "CloudTrailEvent" in data["events"][0]
    assert mock_le.call_args.kwargs["LookupAttributes"] == [
        {"AttributeKey": "EventId", "AttributeValue": "evt-abc-123"}
    ]


def test_investigate_event_not_found(patched_client):
    with patch.object(patched_client, "lookup_events", return_value={"Events": []}):
        result = investigate_event({"event_id": "nonexistent"})
    assert result["isError"] is True
    assert "not found" in json.loads(result["content"][0]["text"])["error"]


def test_investigate_event_missing_param(patched_client):
    result = investigate_event({})
    assert result["isError"] is True
    assert "event_id" in json.loads(result["content"][0]["text"])["error"]


def test_investigate_event_lookback_clamped(patched_client):
    evt = _make_ct_event(event_id="evt-001")
    with patch.object(patched_client, "lookup_events", return_value={"Events": [evt]}):
        result = investigate_event({"event_id": "evt-001", "lookback_days": 999})
    assert json.loads(result["content"][0]["text"])["lookback_days"] == MAX_LOOKBACK_DAYS
