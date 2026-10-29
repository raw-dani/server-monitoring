"""Unit tests for website checking and status code resolution."""

from unittest.mock import patch

from shsm.collectors.websites import check_single_website


def test_check_single_website_fallback_when_expected_status_json_empty():
    site = {
        "domain": "example.com",
        "expected_status_json": "[]",  # Simulates legacy DB empty array
    }
    default_expected = [200, 201, 204, 301, 302, 307, 308, 401, 403]

    with patch("shsm.collectors.websites._check_dns", return_value=(True, ["93.184.216.34"], "")), \
         patch("shsm.collectors.websites._check_http") as mock_check_http:
        mock_check_http.return_value = {"ok": True, "status_code": 200, "response_ms": 50.0}

        res = check_single_website(site, timeout=5.0, user_agent="SHSM-Test", default_expected=default_expected)
        assert res["dns_ok"] is True

        # Verify that _check_http was called with default_expected, NOT []!
        assert mock_check_http.call_count == 2
        for call in mock_check_http.call_args_list:
            expected_arg = call[0][4]
            assert 200 in expected_arg
            assert expected_arg != []


def test_sync_websites_does_not_serialize_empty_expected_status(test_db):
    from datetime import datetime, timezone

    from shsm.database.repositories.inventory import InventoryRepo

    repo = InventoryRepo(test_db)
    now = datetime.now(timezone.utc)
    sites = [
        {"domain": "test1.com", "expected_status": []},
        {"domain": "test2.com", "expected_status": [200, 301]},
    ]
    res = repo.sync_websites(sites, now)
    assert res["added"] == 2

    row1 = test_db.query_one("SELECT expected_status_json FROM websites WHERE domain='test1.com'")
    assert row1["expected_status_json"] is None

    row2 = test_db.query_one("SELECT expected_status_json FROM websites WHERE domain='test2.com'")
    assert row2["expected_status_json"] == "[200, 301]"


def test_check_http_timeout_distinction():
    import requests
    from shsm.collectors.websites import _check_http

    with patch("requests.Session.get", side_effect=requests.exceptions.Timeout("Read timed out")):
        res = _check_http("example.com", "https", timeout=1.0, user_agent="SHSM-Test", expected_statuses=[200], retries=1)
        assert res["ok"] is False
        assert res["error_type"] == "timeout"
        assert "timed out" in res["error"].lower()


def test_website_collector_timeout_classified_as_probe_timeout(test_db, sample_config):
    from shsm.collectors.websites import collect
    from shsm.core.context import Context
    from shsm.core.findings import CheckStatus, Severity

    ctx = Context(sample_config, test_db)
    ctx.inventory.sync_websites([{"domain": "timeout-site.com"}], ctx.now())

    with patch("shsm.collectors.websites.check_single_website") as mock_single:
        mock_single.return_value = {
            "site": ctx.inventory.active_websites()[0],
            "dns_ok": True,
            "ips": ["1.2.3.4"],
            "dns_err": "",
            "http": {"ok": False, "status_code": None, "response_ms": 1000.0, "chain": [], "https_redirect": False, "error_type": "timeout", "error": "Connection timed out after 10.0s"},
            "https": {"ok": False, "status_code": None, "response_ms": 1000.0, "chain": [], "https_redirect": False, "error_type": "timeout", "error": "Connection timed out after 10.0s"},
        }

        output = collect(ctx)
        findings = [f for f in output.findings if f.key == "timeout-site.com"]
        assert len(findings) == 1
        assert "probe timed out" in findings[0].title.lower()
        assert findings[0].severity != Severity.CRITICAL
