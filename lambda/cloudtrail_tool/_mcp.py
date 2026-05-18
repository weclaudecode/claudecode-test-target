import json

DELIMITER = "___"


def get_tool_name(context) -> str:
    raw = context.client_context.custom["bedrockAgentCoreToolName"]
    if DELIMITER in raw:
        return raw[raw.index(DELIMITER) + len(DELIMITER):]
    return raw


def success(data) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps(data, default=str, indent=2)}],
        "isError": False,
    }


def error(message: str, details: dict = None) -> dict:
    payload = {"error": message}
    if details:
        payload["details"] = details
    return {
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "isError": True,
    }
