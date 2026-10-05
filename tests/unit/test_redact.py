"""Unit tests for secret redaction utility."""

from shsm.utils.redact import mask_email, mask_ip, redact, redact_mapping


def test_redact_password_in_string():
    raw = "Connecting with password=SuperSecretPassword123! to database"
    redacted = redact(raw)
    assert "SuperSecretPassword123!" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_mysql_and_db_passwords():
    raw = "mysql -u root --password SuperSecretPass99! mydb"
    redacted = redact(raw)
    assert "SuperSecretPass99!" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_authorization_bearer():
    raw = "curl -H 'Authorization: Bearer abcd1234efgh5678ijkl' https://api.example.com"
    redacted = redact(raw)
    assert "abcd1234efgh5678ijkl" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_mapping():
    data = {
        "user": "admin",
        "api_key": "secret-api-token-999",
        "password_hash": "$2y$10$abcdefghij",
        "normal_field": "visible_data",
        "nested": {
            "token": "nested-secret",
            "count": 42,
        },
    }
    redacted = redact_mapping(data)
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["password_hash"] == "[REDACTED]"
    assert redacted["normal_field"] == "visible_data"
    assert redacted["nested"]["token"] == "[REDACTED]"
    assert redacted["nested"]["count"] == 42


def test_mask_ip():
    assert mask_ip("192.168.1.100") == "192.168.1.0/24"
    assert mask_ip("10.0.0.1") == "10.0.0.0/24"


def test_mask_email():
    assert mask_email("rohmataliwardani@gmail.com") == "r***@gmail.com"
    assert mask_email("admin@server.local") == "a***@server.local"
