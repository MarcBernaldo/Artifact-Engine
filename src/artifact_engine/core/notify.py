"""Telling something outside the case that a run finished.

An unattended triage is only unattended if somebody learns it is done. That is
the whole feature, and it is also the most dangerous one in this repository,
because it is the only code whose PURPOSE is to send content off this machine.

Three rules follow from that, and none of them is a preference.

**Metadata only, by allow-list.** What leaves is named here, one key at a time.
Not a denylist: `run-summary.json` grows -- `tools` in v0.7.39, `totals.cached` in
v0.7.51, five keys in v0.7.53 -- and under a denylist every future key is
published by default until somebody remembers to exclude it. A hostname would
reach a chat service because nobody edited a list. So counts travel, lists of
names do not: `errors` and `incomplete_acquisitions` become their LENGTHS,
`per_machine` never leaves at all (machine names are hostnames), and every
string that goes is one this project controls: the tool's name and version,
the status, parser ids, the finish time, and the label -- which the operator
chose, or which is a digest of the path.

**The label is chosen, never derived.** A case directory is routinely named after
the client, the site or the incident. So the operator says what they are willing
to disclose (`notify_label`), and when they have not said, the run is announced
under a digest of the case path: stable across runs of the same case, and
meaningless to anyone who does not already have the path.

**A notifier outage never changes a verdict.** The evidence was processed and the
outputs are on disk; whether a chat service accepted a message has nothing to do
with either. Every failure here is a warning, and the caller ignores the result.

One more, particular to this: the token is IN the url for every chat service
worth naming -- a webhook's is written into `notify_url`, Telegram's request url
is built from the token the environment supplies -- so anything that prints the
url prints the credential. `requests`'
own `raise_for_status()` puts the url in the exception message, which is why this
module reads `status_code` by hand and never calls it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from artifact_engine.logging_setup import get_logger

log = get_logger()

BACKENDS = ("none", "stdout", "webhook", "telegram")

# Telegram's credentials come from the ENVIRONMENT and from nowhere else. The token
# authenticates as the bot, and a config file is the wrong home for it: every run
# reads the config, `aeng config` names its sources, and a folder copied between
# hosts carries it along. An environment set by the service manager -- a systemd
# `EnvironmentFile` readable by root alone -- keeps it out of every file the engine
# reads or writes. The names are the ones an unattended deployment already declares.
TELEGRAM_TOKEN_ENV = "ARTIFACT_NOTIFY_TELEGRAM_TOKEN"
TELEGRAM_CHAT_ENV = "ARTIFACT_NOTIFY_TELEGRAM_CHAT_ID"
_TELEGRAM_API = "https://api.telegram.org"


def redact(url: str) -> str:
    """A webhook url with the secret taken out, for the one place it is logged."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    if not parts.scheme or not parts.netloc:
        return "<malformed url>"
    return f"{parts.scheme}://{parts.netloc}/..."


def label_for(root: Path | str, configured: str = "") -> str:
    """The name this run is announced under -- never the case directory's own."""
    chosen = (configured or "").strip()
    if chosen:
        return chosen
    digest = hashlib.sha256(str(Path(root).resolve()).encode("utf-8")).hexdigest()
    return f"case-{digest[:8]}"


def build_event(summary: dict, label: str) -> dict:
    """The announcement, built from `run-summary.json` and from nothing else.

    From the FILE rather than from engine state, so what is announced is what is
    on disk: a summary that failed to write, or wrote something different from
    what the run believed, must not be contradicted by the message about it.

    Every value below is a number, an identifier this project invented, a
    timestamp, or the label the operator chose (else a digest of the path).
    Read the list as the specification it is -- anything not here does not
    leave this machine.
    """
    totals = summary.get("totals") or {}
    tools = summary.get("tools") or {}
    return {
        "tool": "artifact-engine",
        "version": (summary.get("engine") or {}).get("version", ""),
        "case": label,
        "status": summary.get("status", ""),
        "machines": summary.get("machines", 0),
        "finished_at": summary.get("finished_at", ""),
        "duration_seconds": summary.get("duration_seconds"),
        "parsers": {k: totals.get(k, 0) for k in ("ok", "cached", "skipped", "errors")},
        # Lengths, not contents: an error string carries the path it failed on and
        # an acquisition entry carries the archive's name.
        "parser_errors": len(summary.get("errors") or []),
        "incomplete_acquisitions": len(summary.get("incomplete_acquisitions") or []),
        "waiting_acquisitions": len(summary.get("waiting_acquisitions") or []),
        # Parser ids are this engine's own vocabulary (`evtx_security`, `sum`),
        # so naming them says what the INSTALLATION could not do and nothing
        # about the case. `missing` is left out: its reasons can quote a path.
        "parsers_blocked": list(tools.get("parsers_blocked") or []),
        "tools_missing": tools.get("tools_missing", 0),
    }


def _send_stdout(event: dict, url: str, timeout: int) -> bool:
    """The backend that needs no secret, and the one to test a pipeline with."""
    print(json.dumps(event, ensure_ascii=False, sort_keys=True))
    return True


def _send_webhook(event: dict, url: str, timeout: int) -> bool:
    if not url:
        log.warning("[!] notify: the webhook backend is selected but notify_url is "
                    "empty, so nothing was sent")
        return False
    import requests

    resp = requests.post(url, json=event, timeout=timeout)
    # Not `raise_for_status()`: it builds its message out of the url, and the url
    # is the credential. The status code alone says everything actionable.
    if resp.status_code >= 400:
        log.warning(f"[!] notify: {redact(url)} answered {resp.status_code}")
        return False
    return True


def render_text(event: dict) -> str:
    """The event as a chat message, for a person reading it on a phone.

    Built from the EVENT, never from the summary, so the allow-list in
    `build_event` stays the one specification of what leaves: this only lays out
    fields already chosen. Plain text with no parse mode -- the label is the
    operator's own string, and a markup dialect would need it escaped to arrive as
    written."""
    p = event.get("parsers") or {}
    lines = [
        f"{event.get('tool', '')} {event.get('version', '')} - {event.get('case', '')}",
        f"status: {event.get('status', '')}",
        (f"machines: {event.get('machines', 0)} | parsers ok {p.get('ok', 0)}, "
         f"cached {p.get('cached', 0)}, skipped {p.get('skipped', 0)}, "
         f"errors {p.get('errors', 0)}"),
        (f"parser errors: {event.get('parser_errors', 0)} | "
         f"incomplete acquisitions: {event.get('incomplete_acquisitions', 0)} | "
         f"waiting: {event.get('waiting_acquisitions', 0)}"),
    ]
    blocked = event.get("parsers_blocked") or []
    if blocked:
        lines.append(f"cannot run on this host: {', '.join(blocked)}")
    took = event.get("duration_seconds")
    lines.append(f"finished {event.get('finished_at', '')}"
                 + (f" in {round(took)} s" if isinstance(took, (int, float)) else ""))
    return "\n".join(lines)


def telegram_note() -> str:
    """What `aeng config` says about the telegram backend: whether each secret is
    set in this process's environment, never what it is."""
    def state(name: str) -> str:
        return "set" if os.environ.get(name, "").strip() else "NOT set"

    return (f"sends a metadata-only message through Telegram; in this environment "
            f"{TELEGRAM_TOKEN_ENV} {state(TELEGRAM_TOKEN_ENV)}, "
            f"{TELEGRAM_CHAT_ENV} {state(TELEGRAM_CHAT_ENV)}")


def _telegram_reason(resp, token: str) -> str:
    """Telegram's own description of a rejection ("chat not found", "Unauthorized"),
    which is what the operator acts on. Read defensively: a proxy can answer instead,
    and the token is cut out of whatever came back."""
    try:
        said = str((resp.json() or {}).get("description") or "")
    except Exception:  # noqa: BLE001 - an answer that is not Telegram's is no reason
        return ""
    said = said.replace(token, "<token>")[:120]
    return f" ({said})" if said else ""


def _send_telegram(event: dict, url: str, timeout: int) -> bool:
    token = os.environ.get(TELEGRAM_TOKEN_ENV, "").strip()
    chat = os.environ.get(TELEGRAM_CHAT_ENV, "").strip()
    unset = [name for name, value in ((TELEGRAM_TOKEN_ENV, token), (TELEGRAM_CHAT_ENV, chat))
             if not value]
    if unset:
        log.warning(f"[!] notify: the telegram backend is selected but {' and '.join(unset)} "
                    f"{'is' if len(unset) == 1 else 'are'} not set in the environment, "
                    f"so nothing was sent")
        return False
    import requests

    resp = requests.post(f"{_TELEGRAM_API}/bot{token}/sendMessage",
                         json={"chat_id": chat, "text": render_text(event),
                               "disable_web_page_preview": True},
                         timeout=timeout)
    if resp.status_code >= 400:
        log.warning(f"[!] notify: {redact(_TELEGRAM_API)} answered {resp.status_code}"
                    f"{_telegram_reason(resp, token)}")
        return False
    return True


_SENDERS = {"stdout": _send_stdout, "webhook": _send_webhook, "telegram": _send_telegram}


def send(summary: dict, root: Path | str, backend: str = "none", url: str = "",
         label: str = "", timeout: int = 10) -> bool:
    """Announce a finished run. Never raises, whatever happens inside."""
    backend = (backend or "none").strip().lower()
    if backend in ("", "none"):
        return False
    sender = _SENDERS.get(backend)
    if sender is None:
        log.warning(f"[!] notify: unknown backend {backend!r} "
                    f"(known: {', '.join(BACKENDS)}); nothing was sent")
        return False
    try:
        event = build_event(summary, label_for(root, label))
        return sender(event, url, timeout)
    except Exception as e:  # noqa: BLE001 - a notifier must not decide a case
        # Only the type: an exception's message is written by whatever library
        # raised it, and `requests` builds several of its own out of the url.
        log.warning(f"[!] notify: {backend} backend failed ({type(e).__name__}); "
                    f"the run is unaffected")
        return False
