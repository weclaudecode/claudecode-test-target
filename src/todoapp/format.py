from __future__ import annotations

from todoapp.core import Todo


def format_for_display(todo: Todo) -> str:
    marker = "x" if todo.done else " "
    return f"[{marker}] {todo.title}"
