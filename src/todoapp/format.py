"""Incompatible format module — intentionally different signature to force
a rebase conflict against main's version. This is a test fixture for
rebase-pr.sh integration testing."""

from .core import Todo


def format_for_display(todo: Todo) -> dict:
    """Returns a dict instead of a string — incompatible with main."""
    return {"done": todo.done, "title": todo.title}
