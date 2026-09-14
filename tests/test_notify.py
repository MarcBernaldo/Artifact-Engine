"""The only code in the tool whose purpose is to send something off this machine.

So most of what is tested here is what it must NOT do: carry a hostname, a path,
an account or a case name into a message; print the credential that sits inside a
webhook url; or let a notifier outage change the verdict on a case that was
processed perfectly well. Every value below is invented -- see "Case data never
becomes text" in CLAUDE.md.
"""
from __future__ import annotations

import inspect
import json
import logging

import pytest
import requests

from artifact_engine import cli, config
from artifact_engine.core import notify

_TOKEN = "T0KEN-must-never-print"
_URL = f"https://hooks.example.local/services/{_TOKEN}?sig={_TOKEN}"


def _summary() -> dict:
    """A summary shaped like a real one, salted with everything that must stay."""
    return {
        "schema_version": 1,
        "engine": {"version": "9.9.9", "python": "3.13.0", "os": "Linux",
                   "os_release": "6.8"},
        "generated": "2026-02-11 12:00:00 UTC",
        "started_at": "2026-02-11T11:50:00Z",
        "finished_at": "2026-02-11T12:00:00Z",
        "duration_seconds": 600.0,
        "status": "incomplete",
        "machines": 2,
        "totals": {"ok": 40, "cached": 3, "skipped": 20, "errors": 1},
        "per_machine": [
            {"machine": "HOST-01", "os": "windows", "collector": "kape", "ok": 20},
            {"machine": "srv-files-02_uac", "os": "linux", "collector": "uac", "ok": 20},
        ],
        "errors": ["HOST-01 / evtx_security: failed on /cases/example-corp/HOST-01/C/"
                   "Users/jdoe/NTUSER.DAT"],
        "incomplete_acquisitions": [{"archive": "HOST-01_kape_example-corp.zip",
                                     "status": "partial",
                                     "detail": "CRC error in Users/jdoe/Desktop"}],
        "tools": {"tools_needed": 3, "tools_missing": 1, "parsers_total": 60,
                  "parsers_blocked": ["deepblue"], "archiver_present": True,
                  "missing": [{"binary": "DeepBlue.ps1", "parsers": ["deepblue"],
                               "reason": "not found under /opt/example-corp/tools"}]},
    }


_CASE_ROOT = "/cases/example-corp-incident-42"


# --------------------------------------------------------------------------- #
# What leaves
# --------------------------------------------------------------------------- #
def test_nothing_that_names_the_evidence_reaches_the_event():
    """The rule this module exists under. Hostnames, accounts, paths, archive
    names and the case name are all present in the summary above, and none of
    them may be in what is sent."""
    event = notify.build_event(_summary(), notify.label_for(_CASE_ROOT))
    text = json.dumps(event)

    for leaked in ("HOST-01", "srv-files-02", "jdoe", "example-corp", "NTUSER",
                   "/cases", "/opt", ".zip", "incident-42"):
        assert leaked not in text, f"{leaked!r} reached the event"


def test_the_event_is_an_allow_list_and_a_new_key_is_a_decision():
    """A denylist publishes every future summary key by default. Pinning the exact
    key set means adding one to the event is a change somebody has to make here,
    on purpose, and justify."""
    event = notify.build_event(_summary(), "case-x")

    assert set(event) == {
        "tool", "version", "case", "status", "machines", "finished_at",
        "duration_seconds", "parsers", "parser_errors", "incomplete_acquisitions",
        "parsers_blocked", "tools_missing",
    }


def test_lists_that_carry_names_travel_as_their_lengths():
    event = notify.build_event(_summary(), "case-x")

    assert event["parser_errors"] == 1
    assert event["incomplete_acquisitions"] == 1
    assert event["parsers"] == {"ok": 40, "cached": 3, "skipped": 20, "errors": 1}
    # Parser ids are the engine's own vocabulary, not case content.
    assert event["parsers_blocked"] == ["deepblue"]


# --------------------------------------------------------------------------- #
# What it is announced under
# --------------------------------------------------------------------------- #
def test_a_configured_label_is_used_as_written():
    assert notify.label_for(_CASE_ROOT, "  triage-A  ") == "triage-A"


def test_without_one_the_case_travels_as_a_digest_and_never_its_name():
    """A case directory is routinely named after the client or the incident."""
    label = notify.label_for(_CASE_ROOT)

    assert label.startswith("case-") and len(label) == len("case-") + 8
    assert "example" not in label and "42" not in label.replace(label[5:], "")
    assert notify.label_for(_CASE_ROOT) == label, "stable across runs of one case"
    assert notify.label_for(_CASE_ROOT + "-other") != label


# --------------------------------------------------------------------------- #
# The credential in the url
# --------------------------------------------------------------------------- #
def test_redaction_keeps_the_host_and_drops_the_secret():
    shown = notify.redact(_URL)

    assert shown == "https://hooks.example.local/..."
    assert _TOKEN not in shown


@pytest.mark.parametrize("bad", ["", "not a url", "hooks.example.local/x"])
def test_a_malformed_url_is_described_not_echoed(bad):
    assert notify.redact(bad) in ("<malformed url>", "<unparseable url>")


def test_a_rejected_post_names_the_host_and_not_the_token(monkeypatch, caplog):
    class _Resp:
        status_code = 403

    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="webhook", url=_URL) is False

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "403" in said and "hooks.example.local" in said
    assert _TOKEN not in said


def test_an_exception_quoting_the_url_does_not_carry_it_into_the_log(monkeypatch,
                                                                    caplog):
    """`requests` builds several of its own messages out of the url -- the
    connection errors do, and `raise_for_status` does. Only the type is logged."""
    def _boom(url, **_):
        raise requests.ConnectionError(f"Max retries exceeded with url: {url}")

    monkeypatch.setattr(requests, "post", _boom)
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="webhook", url=_URL) is False

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "ConnectionError" in said
    assert _TOKEN not in said and "services" not in said


def test_the_module_never_calls_raise_for_status():
    source = inspect.getsource(notify)
    code = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#"))
    assert "raise_for_status()" not in code.replace("`raise_for_status()`", "")


# --------------------------------------------------------------------------- #
# Fail-soft, and off unless asked
# --------------------------------------------------------------------------- #
def test_off_by_default_sends_nothing_and_prints_nothing(monkeypatch, capsys):
    monkeypatch.setattr(requests, "post",
                        lambda *a, **k: pytest.fail("posted with notify off"))

    assert config.Config().notify == "none"
    assert notify.send(_summary(), _CASE_ROOT) is False
    assert capsys.readouterr().out == ""


def test_the_stdout_backend_needs_no_secret(capsys):
    assert notify.send(_summary(), _CASE_ROOT, backend="stdout") is True

    event = json.loads(capsys.readouterr().out)
    assert event["status"] == "incomplete" and event["machines"] == 2


def test_a_webhook_with_no_url_says_so_and_posts_nothing(monkeypatch, caplog):
    monkeypatch.setattr(requests, "post",
                        lambda *a, **k: pytest.fail("posted with no url"))
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="webhook") is False
    assert any("notify_url is empty" in r.getMessage() for r in caplog.records)


def test_an_unknown_backend_is_a_warning_not_a_crash(caplog):
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="carrier-pigeon") is False
    assert any("unknown backend" in r.getMessage() for r in caplog.records)


def test_a_broken_summary_does_not_escape_either(caplog):
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send({"totals": "not a dict"}, _CASE_ROOT,
                           backend="stdout") is False


def test_the_run_never_lets_the_notifier_decide_its_exit_code():
    """The result of `send` is discarded in `cmd_run`, and asserted to be: a
    notifier outage must not turn a processed case into a failed one."""
    source = inspect.getsource(cli.cmd_run)

    assert "notify.send(" in source
    for use in ("= notify.send(", "if notify.send(", "not notify.send(",
                "return notify.send("):
        assert use not in source


def test_the_settings_load_from_the_config_file(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("notify: webhook\nnotify_url: https://hooks.example.local/x\n"
                        "notify_label: triage-A\nnotify_timeout: 3\n", encoding="utf-8")
    monkeypatch.setattr(config, "install_dir", lambda: None)
    monkeypatch.setattr(config, "user_config_dir", lambda: tmp_path / "nouser")

    cfg = config.load_config(cfg_file)

    assert (cfg.notify, cfg.notify_label, cfg.notify_timeout) == ("webhook", "triage-A", 3)
    assert cfg.notify_url == "https://hooks.example.local/x"


# --------------------------------------------------------------------------- #
# Telegram: the same event as a chat message, its secrets from the environment
# --------------------------------------------------------------------------- #
_BOT = "123456789:AAExampleBotTokenThatMustNeverPrint"
_CHAT = "10000001"


def _telegram_env(monkeypatch, token=_BOT, chat=_CHAT):
    for name, value in ((notify.TELEGRAM_TOKEN_ENV, token), (notify.TELEGRAM_CHAT_ENV, chat)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def _logged(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


def test_the_telegram_message_is_laid_out_from_the_event_and_nothing_else():
    text = notify.render_text(notify.build_event(_summary(), notify.label_for(_CASE_ROOT)))

    for leaked in ("HOST-01", "srv-files-02", "jdoe", "example-corp", "NTUSER",
                   "/cases", "/opt", ".zip", "incident-42"):
        assert leaked not in text, f"{leaked!r} reached the message"
    assert "status: incomplete" in text and "errors 1" in text and "deepblue" in text


def test_telegram_sends_that_message_to_the_configured_chat(monkeypatch):
    _telegram_env(monkeypatch)
    posted: dict = {}

    class _Resp:
        status_code = 200

    def _post(url, json=None, timeout=None):
        posted.update(url=url, body=json)
        return _Resp()

    monkeypatch.setattr(requests, "post", _post)

    assert notify.send(_summary(), _CASE_ROOT, backend="telegram") is True
    assert posted["url"] == f"https://api.telegram.org/bot{_BOT}/sendMessage"
    assert posted["body"]["chat_id"] == _CHAT
    assert posted["body"]["text"] == notify.render_text(
        notify.build_event(_summary(), notify.label_for(_CASE_ROOT)))


def test_a_rejected_telegram_message_says_why_and_never_the_token(monkeypatch, caplog):
    _telegram_env(monkeypatch)

    class _Resp:
        status_code = 400

        def json(self):
            return {"ok": False, "description": f"Bad Request: chat not found (bot{_BOT})"}

    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="telegram") is False

    said = _logged(caplog)
    assert "400" in said and "chat not found" in said
    assert _BOT not in said and _BOT.split(":")[1] not in said


def test_an_exception_quoting_the_telegram_url_leaves_the_token_out(monkeypatch, caplog):
    _telegram_env(monkeypatch)

    def _boom(url, **_):
        raise requests.ConnectionError(f"Max retries exceeded with url: {url}")

    monkeypatch.setattr(requests, "post", _boom)
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="telegram") is False

    said = _logged(caplog)
    assert "ConnectionError" in said
    assert _BOT not in said


@pytest.mark.parametrize("token, chat, named", [
    (None, _CHAT, notify.TELEGRAM_TOKEN_ENV),
    (_BOT, None, notify.TELEGRAM_CHAT_ENV),
    ("  ", "", notify.TELEGRAM_TOKEN_ENV),
])
def test_telegram_without_its_secrets_sends_nothing_and_names_what_is_missing(
        monkeypatch, caplog, token, chat, named):
    _telegram_env(monkeypatch, token, chat)
    monkeypatch.setattr(requests, "post",
                        lambda *a, **k: pytest.fail("posted without credentials"))
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert notify.send(_summary(), _CASE_ROOT, backend="telegram") is False

    said = _logged(caplog)
    assert named in said and "nothing was sent" in said
    assert _BOT not in said


def test_the_telegram_token_is_never_taken_from_a_config_file(monkeypatch, tmp_path):
    """A config file is read by every run and a folder copy carries it to the next
    host, so a token written there is ignored rather than used."""
    _telegram_env(monkeypatch, None, None)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"notify: telegram\nnotify_url: https://api.telegram.org/bot{_BOT}/x\n"
                        f"{notify.TELEGRAM_TOKEN_ENV}: {_BOT}\n"
                        f"{notify.TELEGRAM_CHAT_ENV}: {_CHAT}\n", encoding="utf-8")
    monkeypatch.setattr(config, "install_dir", lambda: None)
    monkeypatch.setattr(config, "user_config_dir", lambda: tmp_path / "nouser")
    monkeypatch.setattr(requests, "post",
                        lambda *a, **k: pytest.fail("the token was taken from the config file"))

    cfg = config.load_config(cfg_file)

    assert cfg.notify == "telegram"
    assert notify.send(_summary(), _CASE_ROOT, backend=cfg.notify, url=cfg.notify_url,
                       label=cfg.notify_label) is False


def test_aeng_config_says_whether_each_telegram_secret_is_set_never_its_value(monkeypatch):
    _telegram_env(monkeypatch, _BOT, None)

    note = notify.telegram_note()

    assert f"{notify.TELEGRAM_TOKEN_ENV} set" in note
    assert f"{notify.TELEGRAM_CHAT_ENV} NOT set" in note
    assert _BOT not in note and _BOT.split(":")[1] not in note
