import time

import boto3

from .._guardrails import GuardrailExceeded, assert_scan_within_budget
from .._mcp import error, success

# Lake query APIs (StartQuery, DescribeQuery, GetQueryResults) are on cloudtrail,
# not cloudtrail-data. Variable named cloudtrail_data per task spec.
cloudtrail_data = boto3.client("cloudtrail")

_DEFAULT_TIMEOUT = 30
_MAX_TIMEOUT = 60
_POLL_INTERVAL = 1


def _poll_until_finished(query_id: str, timeout_seconds: int) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        resp = cloudtrail_data.describe_query(QueryId=query_id)
        status = resp["QueryStatus"]
        if status == "FINISHED":
            return resp
        if status in ("FAILED", "CANCELLED", "TIMED_OUT"):
            raise RuntimeError(f"Query {query_id} ended with status {status}")
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"Query {query_id} did not finish within {timeout_seconds}s")


def _collect_results(query_id: str) -> list:
    rows = []
    kwargs: dict = {"QueryId": query_id}
    while True:
        page = cloudtrail_data.get_query_results(**kwargs)
        rows.extend(page.get("QueryResultRows", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
    return rows


def analytical_query(event: dict) -> dict:
    arn = event.get("event_data_store_arn")
    sql = event.get("sql")
    if not arn:
        return error("Missing required param: event_data_store_arn")
    if not sql:
        return error("Missing required param: sql")

    timeout = min(int(event.get("timeout_seconds", _DEFAULT_TIMEOUT)), _MAX_TIMEOUT)

    # Step A: EXPLAIN preflight — estimate scan cost before running the real query
    explain_resp = cloudtrail_data.start_query(QueryStatement=f"EXPLAIN {sql}")
    explain_qid = explain_resp["QueryId"]
    describe_resp = _poll_until_finished(explain_qid, timeout)

    estimated_bytes = describe_resp.get("QueryStatistics", {}).get(
        "EstimatedTotalScanSizeBytes", 0
    )
    try:
        assert_scan_within_budget(estimated_bytes)
    except GuardrailExceeded as exc:
        return error(str(exc))

    # Step B: actual query, only reached if preflight passed
    t0 = time.monotonic()
    run_resp = cloudtrail_data.start_query(QueryStatement=sql)
    run_qid = run_resp["QueryId"]
    describe_run = _poll_until_finished(run_qid, timeout)
    runtime_ms = int((time.monotonic() - t0) * 1000)

    scanned_bytes = describe_run.get("QueryStatistics", {}).get("BytesScanned", 0)
    rows = _collect_results(run_qid)

    return success({"rows": rows, "scanned_bytes": scanned_bytes, "runtime_ms": runtime_ms})


TOOLS = {"analytical_query": analytical_query}
