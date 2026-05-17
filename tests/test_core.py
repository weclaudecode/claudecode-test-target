from todoapp.core import _store, add_todo


def setup_function() -> None:
    _store.clear()


def test_add_todo_assigns_id() -> None:
    t = add_todo("walk the dog")
    assert t.id >= 1
    assert t.title == "walk the dog"
    assert t.done is False


def test_add_todo_appends_to_store() -> None:
    add_todo("first")
    add_todo("second")
    assert len(_store) == 2
