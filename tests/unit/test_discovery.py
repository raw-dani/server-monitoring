"""Unit tests for website and WordPress discovery."""

import os
from unittest.mock import MagicMock, patch

from shsm.discovery.cyberpanel import (
    discover_from_cyberpanel_mariadb,
    discover_from_home_directories,
    discover_from_lsws_conf,
    discover_websites,
)
from shsm.discovery.wordpress import (
    discover_wordpress_sites,
    is_wordpress_installation,
)


def test_discover_from_cyberpanel_mariadb():
    ctx = MagicMock()
    mock_tsv = (
        "atonergi.com\tadmin@atonergi.com\tatone9471\t/home/atonergi.com/public_html\n"
        "suklayskin.com\tadmin@suklayskin.com\tsukla16\t\n"
    )

    with patch("shsm.collectors.mariadb.run_query") as mock_query:
        # First query for websites returns mock_tsv, second query for subdomains returns empty
        mock_query.side_effect = [
            (True, mock_tsv, ""),
            (False, "", "no table"),
        ]

        sites = discover_from_cyberpanel_mariadb(ctx)
        assert len(sites) == 2
        assert sites[0]["domain"] == "atonergi.com"
        assert sites[0]["doc_root"] == "/home/atonergi.com/public_html"
        assert sites[0]["owner"] == "atone9471"
        assert sites[0]["source"] == "cyberpanel_mariadb"

        assert sites[1]["domain"] == "suklayskin.com"
        assert sites[1]["doc_root"] == "/home/suklayskin.com/public_html"
        assert sites[1]["owner"] == "sukla16"


def test_discover_from_lsws_conf_parses_httpd_config(tmp_path):
    httpd_conf = tmp_path / "httpd_config.conf"
    httpd_conf.write_text(
        """
virtualhost Example {
  vhRoot                  /usr/local/lsws/Example/
  configFile              conf/vhosts/Example/vhconf.conf
}

virtualhost mydomain.com {
  vhRoot                  /home/mydomain.com
  configFile              /usr/local/lsws/conf/vhosts/mydomain.com/vhost.conf
}
""",
        encoding="utf-8",
    )

    sites = discover_from_lsws_conf(vhost_dir=str(tmp_path / "vhosts"), httpd_conf=str(httpd_conf))
    assert len(sites) == 1
    assert sites[0]["domain"] == "mydomain.com"
    assert sites[0]["doc_root"] == "/home/mydomain.com/public_html"
    assert sites[0]["source"] == "lsws_httpd_conf"


def test_discover_from_home_directories_resilient(tmp_path):
    # Valid site
    site_dir = tmp_path / "valid-site.com" / "public_html"
    site_dir.mkdir(parents=True)

    # Invalid non-domain folder
    (tmp_path / "cyberpanel").mkdir()

    sites = discover_from_home_directories(str(tmp_path))
    assert len(sites) == 1
    assert sites[0]["domain"] == "valid-site.com"
    assert sites[0]["doc_root"] == str(site_dir)


def test_is_wordpress_installation(tmp_path):
    wp_dir = tmp_path / "site1"
    wp_dir.mkdir()
    assert is_wordpress_installation(str(wp_dir)) is False

    (wp_dir / "wp-includes").mkdir()
    (wp_dir / "wp-content").mkdir()
    assert is_wordpress_installation(str(wp_dir)) is True


def test_discover_wordpress_sites_auto_fallback(tmp_path):
    ctx = MagicMock()
    ctx.inventory.active_websites.return_value = []
    ctx.config.get.side_effect = lambda k, d=None: d

    site_dir = tmp_path / "wp-site.com" / "public_html"
    site_dir.mkdir(parents=True)
    (site_dir / "wp-includes").mkdir()
    (site_dir / "wp-content").mkdir()
    (site_dir / "wp-includes" / "version.php").write_text("$wp_version = '6.4.3';", encoding="utf-8")

    with patch("shsm.discovery.cyberpanel.discover_websites") as mock_disc:
        mock_disc.return_value = [
            {"domain": "wp-site.com", "doc_root": str(site_dir)}
        ]
        found = discover_wordpress_sites(ctx)
        assert len(found) == 1
        assert found[0]["domain"] == "wp-site.com"
        assert found[0]["wp_version"] == "6.4.3"


def test_should_ignore_domain_filtering():
    from shsm.discovery.cyberpanel import should_ignore_domain

    # Suspended domains
    assert should_ignore_domain("amertajati.co.id-suspended") is True
    assert should_ignore_domain("aure-studios.com-suspended") is True
    assert should_ignore_domain("test.suspended") is True
    assert should_ignore_domain("amertajati.co.id-suspended", ignore_suspended=False) is False

    # Mail subdomains
    assert should_ignore_domain("mail.amertajati.co.id") is True
    assert should_ignore_domain("webmail.talentaindonesia.com") is True
    assert should_ignore_domain("mail.amertajati.co.id", ignore_mail=False) is False

    # Valid domains
    assert should_ignore_domain("gmteknologi.com") is False
    assert should_ignore_domain("app.gmteknologi.com") is False
    assert should_ignore_domain("atonergi.com") is False

