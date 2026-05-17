# todoapp — orchestrator test target

A minimal Python todo library used as a sacrificial target for the
[claudecode-automation](https://github.com/weclaudecode/claudecode-automation)
orchestrator's end-to-end testing.

This repo deliberately starts with the bare minimum (`add_todo()` and a
single passing test) so that orchestrator-driven plans have realistic
work to do without app-level complexity getting in the way of
orchestrator-level signal.

## Setup

```bash
uv sync --dev
uv run pytest
```

## Backlog — drives test plans

Rough task ideas the test plans will exercise. The plans themselves live
in `.claude/plans/` once authored — the orchestrator kit must be
installed into this repo first (see the kit's README in the source repo).

1. **Add `complete_todo(id)`** — `src/todoapp/core.py` + tests
2. **Add `list_todos(status=None)`** — `src/todoapp/core.py` + tests
   _Parallel-safe candidate with task 1: different functions, same file →
   exercises the scheduler's `touches:` collision detection (Phase 4 of
   SDLC-EVOLUTION-PLAN)._
3. **Add `format_for_display(todo)` util** — new `src/todoapp/format.py` + tests
   _Parallel-safe with 1 and 2: disjoint files. Should run concurrently._
4. **Add CLI entry point** — new `src/todoapp/cli.py`
   _Depends on 1, 2, 3. Exercises dependency-blocked-task waiting._
5. **Add SQLite persistence** — new `src/todoapp/db.py` + `migrations/001_init.sql`
   _Sensitive: touches `migrations/` → should trigger `orch:needs-robbie`
   and auto-merge disabled._
6. **Add IAM role for future Lambda deploy** — new `infra/iam.tf`
   _Sensitive: hits the IAM pattern detector → ingest flags it; reviewer
   `safety_block` category should kick in (Phase 3)._

<!-- sweep-merges smoke fixture -->
