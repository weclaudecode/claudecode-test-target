import importlib
import pkgutil

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

from . import tools as _tools_pkg
from ._mcp import error, get_tool_name

logger = Logger()
tracer = Tracer()


def discover_tools() -> dict:
    tools_map = {}
    for module_info in pkgutil.iter_modules(_tools_pkg.__path__):
        module = importlib.import_module(f".tools.{module_info.name}", package=__package__)
        if hasattr(module, "TOOLS"):
            tools_map.update(module.TOOLS)
    return tools_map


@logger.inject_lambda_context
@tracer.capture_lambda_handler
def handler(event: dict, context: LambdaContext) -> dict:
    tool_name = get_tool_name(context)
    logger.info("Tool invoked", tool_name=tool_name)

    try:
        tools_map = discover_tools()
        if tool_name not in tools_map:
            return error(f"Unknown tool: {tool_name}")
        return tools_map[tool_name](event)
    except Exception as e:
        logger.exception("Tool execution failed", tool_name=tool_name)
        return error(str(e), {"tool": tool_name})
