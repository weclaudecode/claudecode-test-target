import json
from unittest.mock import MagicMock, patch

import pytest

from cloudtrail_tool.handler import handler


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


def test_unknown_tool_returns_error():
    ctx = make_context("nonexistent_tool")
    result = handler({}, ctx)

    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert "Unknown tool" in body["error"]
    assert "nonexistent_tool" in body["error"]


def test_tool_exception_becomes_error_response():
    def boom(event):
        raise ValueError("something went wrong")

    ctx = make_context("broken_tool")
    with patch("cloudtrail_tool.handler.discover_tools", return_value={"broken_tool": boom}):
        result = handler({}, ctx)

    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert "something went wrong" in body["error"]
    assert body["details"]["tool"] == "broken_tool"
