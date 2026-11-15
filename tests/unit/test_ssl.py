"""Unit tests for SSL certificate inspection and collectors."""

import datetime
from unittest.mock import MagicMock, patch
import socket
import ssl

from shsm.collectors.ssl import collect, inspect_certificate
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, Severity


def test_inspect_certificate_success():
    mock_sock = MagicMock()
    mock_sslsock = MagicMock()
    mock_sslsock.getpeercert.return_value = {
        "notBefore": "Oct 01 00:00:00 2026 GMT",
        "notAfter": "Dec 30 00:00:00 2026 GMT",
    }
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("socket.create_connection") as mock_conn, \
         patch("ssl.create_default_context", return_value=mock_ctx):
        mock_conn.return_value.__enter__.return_value = mock_sock

        res = inspect_certificate("example.com", 443, timeout=5.0)
        assert res["valid"] is True
        assert res["domain"] == "example.com"
        assert res["days_remaining"] is not None
        assert res["days_remaining"] > 0
        assert res["error"] is None


def test_inspect_certificate_timeout_retry():
    with patch("socket.create_connection", side_effect=socket.timeout("The handshake operation timed out")):
        res = inspect_certificate("example.com", 443, timeout=1.0, retries=1)
        assert res["valid"] is False
        assert res["is_timeout"] is True
        assert "timed out" in res["error"].lower()


def test_ssl_collector_timeout_classified_as_warning(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    ctx.inventory.sync_websites([{"domain": "timeout-domain.com"}], ctx.now())

    with patch("shsm.collectors.ssl.inspect_certificate") as mock_inspect:
        mock_inspect.return_value = {
            "domain": "timeout-domain.com",
            "port": 443,
            "valid": False,
            "days_remaining": None,
            "is_timeout": True,
            "error": "The handshake operation timed out",
        }

        output = collect(ctx)
        # Should be WARNING instead of CRITICAL when it's a network handshake timeout
        findings = [f for f in output.findings if f.key == "timeout-domain.com"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "timed out" in findings[0].title.lower()

