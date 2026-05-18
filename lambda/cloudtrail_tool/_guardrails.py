MAX_LOOKBACK_DAYS = 14
MAX_RESULTS = 200
MAX_LAKE_SCAN_BYTES = 1 * 1024**3


class GuardrailExceeded(Exception):
    pass


def clamp_lookback_days(n) -> int:
    return min(int(n), MAX_LOOKBACK_DAYS)


def clamp_result_count(n) -> int:
    return min(int(n), MAX_RESULTS)


def assert_scan_within_budget(estimated_bytes):
    if estimated_bytes > MAX_LAKE_SCAN_BYTES:
        raise GuardrailExceeded(
            f"Query would scan {estimated_bytes:,} bytes; max is {MAX_LAKE_SCAN_BYTES:,} bytes"
        )
