"""Unit tests for Mail queue collector and RBL DNSBL blacklist scanner."""

from unittest.mock import MagicMock, patch

from shsm.collectors.mail_queue import (
    collect as collect_mail,
    get_postfix_queue_counts,
    get_top_queue_senders,
)
from shsm.core.findings import CheckStatus, Severity
from shsm.security.rbl import check_rbl_single, reverse_ip, scan as scan_rbl


def test_reverse_ip():
    assert reverse_ip("192.168.1.100") == "100.1.168.192"
    assert reverse_ip("1.2.3.4") == "4.3.2.1"
    assert reverse_ip("invalid") == "invalid"


def test_mailq_parsing_empty():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/bin/mailq"
    res = MagicMock()
    res.ok = True
    res.stdout = "Mail queue is empty\n"
    ctx.runner.run.return_value = res

    # Patch os.path.isdir to simulate no direct spool access
    with patch("os.path.isdir", return_value=False):
        total, bd, method = get_postfix_queue_counts(ctx)
        assert total == 0
        assert method == "mailq"


def test_mailq_parsing_requests_summary():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/bin/postqueue"
    res = MagicMock()
    res.ok = True
    res.stdout = (
        "-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n"
        "5A8D410068      1248 Sun Oct 26 10:00:00  spammer@badsite.com\n"
        "                                         victim@example.com\n"
        "-- 12 Kbytes in 125 Requests.\n"
    )
    ctx.runner.run.return_value = res

    with patch("os.path.isdir", return_value=False):
        total, bd, method = get_postfix_queue_counts(ctx)
        assert total == 125
        assert method == "mailq"


def test_get_top_queue_senders():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/bin/mailq"
    res = MagicMock()
    res.ok = True
    res.stdout = (
        "5A8D410068  1248 Sun Oct 26 10:00:00  bot@site1.com\n"
        "5A8D410069  1248 Sun Oct 26 10:01:00  bot@site1.com\n"
        "5A8D410070  1248 Sun Oct 26 10:02:00  admin@site2.com\n"
    )
    ctx.runner.run.return_value = res

    top = get_top_queue_senders(ctx)
    assert len(top) == 2
    assert top[0] == ("bot@site1.com", 2)
    assert top[1] == ("admin@site2.com", 1)


from shsm.core.context import Context


def test_collect_mail_clean(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    with patch("shsm.collectors.mail_queue.get_postfix_queue_counts", return_value=(5, {"active": 5}, "spool")), \
         patch("shsm.collectors.mail_queue.check_outbound_spam_connections", return_value=[]):
        out = collect_mail(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert "mail.queue" in checks
        assert checks["mail.queue"].status == CheckStatus.PASS
        assert "mail.outbound_smtp" in checks
        assert checks["mail.outbound_smtp"].status == CheckStatus.PASS
        assert len(out.findings) == 0


def test_collect_mail_spike_and_unauthorized_smtp(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    bad_conn = [{
        "pid": 9999,
        "process": "php-fpm",
        "username": "victim_user",
        "cmdline": "php-fpm: pool victim_user",
        "remote_ip": "198.51.100.5",
        "remote_port": 25,
    }]
    with patch("shsm.collectors.mail_queue.get_postfix_queue_counts", return_value=(850, {"deferred": 850}, "spool")), \
         patch("shsm.collectors.mail_queue.get_top_queue_senders", return_value=[("spammer@evil.com", 800)]), \
         patch("shsm.collectors.mail_queue.check_outbound_spam_connections", return_value=bad_conn):
        out = collect_mail(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["mail.queue"].status == CheckStatus.CRITICAL
        assert checks["mail.outbound_smtp"].status == CheckStatus.CRITICAL
        assert len(out.findings) == 2
        smtp_finding = next(f for f in out.findings if f.check_id == "mail.outbound_smtp")
        assert smtp_finding.severity == Severity.CRITICAL


def test_check_rbl_single_clean():
    with patch("socket.gethostbyname_ex", side_effect=OSError("NXDOMAIN")):
        listed, code = check_rbl_single("4.3.2.1", "zen.spamhaus.org")
        assert listed is False
        assert code == ""


def test_check_rbl_single_listed():
    with patch("socket.gethostbyname_ex", return_value=("zen.spamhaus.org", [], ["127.0.0.2"])):
        listed, code = check_rbl_single("4.3.2.1", "zen.spamhaus.org")
        assert listed is True
        assert code == "127.0.0.2"


def test_scan_rbl_clean(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    with patch("shsm.security.rbl.get_public_ip", return_value="203.0.113.1"), \
         patch("shsm.security.rbl.check_rbl_single", return_value=(False, "")):
        out = scan_rbl(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["security.rbl"].status == CheckStatus.PASS
        assert len(out.findings) == 0


def test_scan_rbl_blacklisted(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    def fake_check(rev_ip, provider, timeout=2.0):
        if "spamhaus" in provider:
            return True, "127.0.0.2"
        return False, ""

    with patch("shsm.security.rbl.get_public_ip", return_value="203.0.113.1"), \
         patch("shsm.security.rbl.check_rbl_single", side_effect=fake_check):
        out = scan_rbl(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["security.rbl"].status == CheckStatus.CRITICAL
        assert len(out.findings) == 1
        assert "is listed on 1 anti-spam blacklist" in out.findings[0].title
