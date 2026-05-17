from __future__ import annotations

from todoapp.core import Todo


def format_for_display(todo: Todo) -> str:
    mark = "x" if todo.done else " "
    return f"[{mark}] {todo.title}"
