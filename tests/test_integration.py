"""End-to-end integration tests through the MCP dispatcher."""
from __future__ import annotations

import datetime
import json
from unittest.mock import MagicMock, patch

import boto3
import moto
import pytest

import cloudtrail_tool.tools.lake as lake_module
import cloudtrail_tool.tools.lookup as lookup_module
import cloudtrail_tool.tools.summarize as summarize_module
from cloudtrail_tool._guardrails import MAX_LAKE_SCAN_BYTES, MAX_LOOKBACK_DAYS
from cloudtrail_tool.handler import discover_tools, handler


def make_context(tool_name: str, target: str = "cloudtrail") -> MagicMock:
    ctx = MagicMock()
    ctx.client_context.custom = {
        "bedrockAgentCoreToolName": f"{target}___{tool_name}",
        "bedrockAgentCoreMessageVersion": "1.0",
        "bedrockAgentCoreAwsRequestId": "test-req-id",
        "bedrockAgentCoreMcpMessageId": "test-mcp-id",
        "bedrockAgentCoreGatewayId": "test-gw-id",
        "bedrockAgentCoreTargetId": "test-target-id",
    }
    return ctx


def _assert_valid_mcp(result: dict) -> dict:
    """Assert MCP response shape and return the parsed body."""
    assert result["isError"] is False
    assert result["content"][0]["type"] == "text"
    return json.loads(result["content"][0]["text"])


_CT_EVENT = {
    "EventId": "evt-integ-001",
    "EventName": "AssumeRole",
    "Username": "alice",
    "EventSource": "sts.amazonaws.com",
    "EventTime": datetime.datetime(2026, 5, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
    "CloudTrailEvent": '{"eventVersion": "1.08", "eventName": "AssumeRole"}',
}

_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/abc-123"
_SQL = f"SELECT eventName FROM {_ARN} LIMIT 10"


@pytest.fixture
def patched_ct_client(monkeypatch, aws_credentials):
    """Moto-backed cloudtrail client injected into both lookup and summarize modules."""
    with moto.mock_aws():
        client = boto3.client("cloudtrail", region_name="us-east-1")
        monkeypatch.setattr(lookup_module, "cloudtrail", client)
        monkeypatch.setattr(summarize_module, "cloudtrail", client)
        yield client


# ─── tool discovery ────────────────────────────────────────────────

def test_discover_tools_finds_all_six():
    tools = discover_tools()
    assert set(tools) == {
        "lookup_by_user",
        "lookup_by_resource",
        "lookup_by_event_name",
        "investigate_event",
        "summarize_window",
        "analytical_query",
    }


# ─── lookup_by_user ────────────────────────────────────────────────

def test_dispatcher_lookup_by_user(patched_ct_client):
    with patch.object(patched_ct_client, "lookup_events", return_value={"Events": [_CT_EVENT]}):
        result = handler({"username": "alice"}, make_context("lookup_by_user"))
    body = _assert_valid_mcp(result)
    assert body["count"] == 1


# ─── lookup_by_resource ────────────────────────────────────────────

def test_dispatcher_lookup_by_resource(patched_ct_client):
    with patch.object(patched_ct_client, "lookup_events", return_value={"Events": [_CT_EVENT]}):
        result = handler({"resource_name": "my-role"}, make_context("lookup_by_resource"))
    body = _assert_valid_mcp(result)
    assert body["count"] == 1


# ─── lookup_by_event_name ──────────────────────────────────────────

def test_dispatcher_lookup_by_event_name(patched_ct_client):
    with patch.object(patched_ct_client, "lookup_events", return_value={"Events": [_CT_EVENT]}):
        result = handler({"event_name": "AssumeRole"}, make_context("lookup_by_event_name"))
    body = _assert_valid_mcp(result)
    assert body["count"] == 1


# ─── investigate_event ─────────────────────────────────────────────

def test_dispatcher_investigate_event(patched_ct_client):
    with patch.object(patched_ct_client, "lookup_events", return_value={"Events": [_CT_EVENT]}):
        result = handler({"event_id": "evt-integ-001"}, make_context("investigate_event"))
    body = _assert_valid_mcp(result)
    assert body["count"] == 1
    assert "CloudTrailEvent" in body["events"][0]


# ─── summarize_window ──────────────────────────────────────────────

def test_dispatcher_summarize_window(patched_ct_client):
    with patch.object(patched_ct_client, "lookup_events", return_value={"Events": [_CT_EVENT]}):
        result = handler({}, make_context("summarize_window"))
    body = _assert_valid_mcp(result)
    assert body["total_events"] == 1
    assert isinstance(body["summary"], list)


# ─── analytical_query ──────────────────────────────────────────────

def test_dispatcher_analytical_query():
    mock_client = MagicMock()
    mock_client.start_query.side_effect = [
        {"QueryId": "explain-qid"},
        {"QueryId": "run-qid"},
    ]
    mock_client.describe_query.side_effect = [
        {
            "QueryStatus": "FINISHED",
            "QueryStatistics": {"EstimatedTotalScanSizeBytes": 1024, "BytesScanned": 0},
        },
        {
            "QueryStatus": "FINISHED",
            "QueryStatistics": {"EstimatedTotalScanSizeBytes": 0, "BytesScanned": 512},
        },
    ]
    mock_client.get_query_results.return_value = {
        "QueryResultRows": [[{"key": "eventName", "value": "AssumeRole"}]]
    }

    with patch.object(lake_module, "cloudtrail_data", mock_client):
        result = handler(
            {"event_data_store_arn": _ARN, "sql": _SQL},
            make_context("analytical_query"),
        )
    body = _assert_valid_mcp(result)
    assert len(body["rows"]) == 1
    assert body["scanned_bytes"] == 512


# ─── guardrail clamp evidence ──────────────────────────────────────

def test_lookback_clamp_at_most_14_days(patched_ct_client):
    """lookback_days=90 must be silently clamped — response shows <= 14."""
    with patch.object(patched_ct_client, "lookup_events", return_value={"Events": [_CT_EVENT]}):
        result = handler(
            {"username": "alice", "lookback_days": 90},
            make_context("lookup_by_user"),
        )
    body = _assert_valid_mcp(result)
    assert body["lookback_days"] <= MAX_LOOKBACK_DAYS
