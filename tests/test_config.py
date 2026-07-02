"""Tests for the .env loader."""
import os

from requiem.core import config


def test_parse_line_variants():
    assert config._parse_line("KEY=value") == ("KEY", "value")
    assert config._parse_line("export KEY=value") == ("KEY", "value")
    assert config._parse_line('KEY="quoted value"') == ("KEY", "quoted value")
    assert config._parse_line("KEY='quoted'") == ("KEY", "quoted")
    assert config._parse_line("  # comment") is None
    assert config._parse_line("") is None
    assert config._parse_line("no_equals_here") is None


def test_load_dotenv_sets_and_respects_precedence(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "VT_API_KEY=fromfile\n"
        "# a comment\n"
        "CAPE_URL='https://cape.lan'\n"
        "VT_API_KEY=laterwins\n"  # within a file, last line wins
    )
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("CAPE_URL", raising=False)

    applied = config.load_dotenv(env)
    assert os.environ["VT_API_KEY"] == "laterwins"
    assert os.environ["CAPE_URL"] == "https://cape.lan"
    assert applied["CAPE_URL"] == "https://cape.lan"


def test_existing_env_var_wins_over_file(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("VT_API_KEY=fromfile\n")
    monkeypatch.setenv("VT_API_KEY", "fromexport")

    config.load_dotenv(env)
    assert os.environ["VT_API_KEY"] == "fromexport"  # not overridden


def test_missing_file_is_safe(tmp_path):
    assert config.load_dotenv(tmp_path / "nope.env") == {}


def test_configured_status_shape():
    status = config.configured_status()
    assert "VT_API_KEY" in status
    assert "CAPE_URL" in status
    assert all(isinstance(v, bool) for v in status.values())
