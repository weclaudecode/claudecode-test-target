import json
from unittest.mock import MagicMock, patch

import pytest

from cloudtrail_tool.tools.lake import analytical_query
from cloudtrail_tool._guardrails import MAX_LAKE_SCAN_BYTES

_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/abc-123"
_SQL = f"SELECT eventName FROM {_ARN} LIMIT 10"


def _finished_describe(estimated_bytes=0, scanned_bytes=0):
    return {
        "QueryStatus": "FINISHED",
        "QueryStatistics": {
            "EstimatedTotalScanSizeBytes": estimated_bytes,
            "BytesScanned": scanned_bytes,
        },
    }


def test_missing_event_data_store_arn_returns_error():
    result = analytical_query({"sql": _SQL})
    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert "event_data_store_arn" in body["error"]


def test_missing_sql_returns_error():
    result = analytical_query({"event_data_store_arn": _ARN})
    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert "sql" in body["error"]


def test_scan_budget_exceeded_returns_error():
    mock_client = MagicMock()
    mock_client.start_query.return_value = {"QueryId": "explain-qid"}
    mock_client.describe_query.return_value = _finished_describe(
        estimated_bytes=MAX_LAKE_SCAN_BYTES + 1
    )

    with patch("cloudtrail_tool.tools.lake.cloudtrail_data", mock_client):
        result = analytical_query({"event_data_store_arn": _ARN, "sql": _SQL})

    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert "bytes" in body["error"].lower()
    # actual query must NOT have been launched
    assert mock_client.start_query.call_count == 1


def test_happy_path_returns_rows():
    mock_client = MagicMock()
    mock_client.start_query.side_effect = [
        {"QueryId": "explain-qid"},
        {"QueryId": "run-qid"},
    ]
    mock_client.describe_query.side_effect = [
        _finished_describe(estimated_bytes=1024),
        _finished_describe(scanned_bytes=512),
    ]
    mock_client.get_query_results.return_value = {
        "QueryResultRows": [
            [{"key": "eventName", "value": "PutObject"}],
            [{"key": "eventName", "value": "GetObject"}],
        ]
    }

    with patch("cloudtrail_tool.tools.lake.cloudtrail_data", mock_client):
        result = analytical_query({"event_data_store_arn": _ARN, "sql": _SQL})

    assert result["isError"] is False
    body = json.loads(result["content"][0]["text"])
    assert len(body["rows"]) == 2
    assert body["scanned_bytes"] == 512
    assert isinstance(body["runtime_ms"], int)
    assert mock_client.start_query.call_count == 2
