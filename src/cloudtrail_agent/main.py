import os

from mcp.client.streamable_http import streamablehttp_client
from strands import Agent, tool  # noqa: F401 — tool re-exported for callers
from strands.tools.mcp import MCPClient

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from .prompt import SYSTEM_PROMPT

_GATEWAY_URL = os.environ.get("AGENTCORE_GATEWAY_ENDPOINT", "")

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: dict, context) -> dict:
    """Handle an AgentCore Runtime invocation by running the Strands agent."""
    user_input = payload.get("inputText", "")

    with MCPClient(lambda: streamablehttp_client(_GATEWAY_URL)) as mcp_client:
        agent = Agent(
            system_prompt=SYSTEM_PROMPT,
            tools=[mcp_client],
            model="anthropic.claude-sonnet-4-6",
        )
        result = agent(user_input)

    return {"output": str(result)}
