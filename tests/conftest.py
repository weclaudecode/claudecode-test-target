import os

# Must be set before aws_lambda_powertools is imported so Tracer becomes a no-op.
os.environ.setdefault("POWERTOOLS_TRACE_DISABLED", "1")
os.environ.setdefault("POWERTOOLS_SERVICE_NAME", "cloudtrail-agent-test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import pytest


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
