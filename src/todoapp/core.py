from __future__ import annotations

from dataclasses import dataclass
from itertools import count

_id_seq = count(1)


@dataclass
class Todo:
    id: int
    title: str
    done: bool = False


_store: list[Todo] = []


def add_todo(title: str) -> Todo:
    todo = Todo(id=next(_id_seq), title=title)
    _store.append(todo)
    return todo
