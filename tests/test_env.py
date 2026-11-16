"""The .env loader: parsing rules and never overriding the real environment."""

from __future__ import annotations

from threatcatalog.env import load_dotenv, parse_env


def test_parse_env_handles_comments_quotes_and_export():
    text = ("# comment\n\nexport OPENAI_API_KEY=sk-abc\nANTHROPIC_API_KEY=\"sk-ant\"\n"
            "BASE='https://gw.example/v1'\nNOTE=value # trailing\nnot a line\n=nokey\n")
    assert parse_env(text) == {"OPENAI_API_KEY": "sk-abc", "ANTHROPIC_API_KEY": "sk-ant",
                               "BASE": "https://gw.example/v1", "NOTE": "value"}


def test_load_dotenv_fills_gaps_but_never_overrides(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("TC_TEST_NEW=from-file\nTC_TEST_SET=from-file\n")
    monkeypatch.delenv("TC_TEST_NEW", raising=False)
    monkeypatch.setenv("TC_TEST_SET", "from-shell")
    loaded = load_dotenv([env])
    import os
    assert os.environ["TC_TEST_NEW"] == "from-file"
    assert os.environ["TC_TEST_SET"] == "from-shell"
    assert loaded == ["TC_TEST_NEW"]
    monkeypatch.delenv("TC_TEST_NEW", raising=False)


def test_load_dotenv_missing_file_is_noop(tmp_path):
    assert load_dotenv([tmp_path / "absent.env"]) == []
