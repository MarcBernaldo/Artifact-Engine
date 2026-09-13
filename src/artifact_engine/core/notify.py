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
worth naming, so anything that prints the url prints the credential. `requests`'
own `raise_for_status()` puts the url in the exception message, which is why this
module reads `status_code` by hand and never calls it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from artifact_engine.logging_setup import get_logger

log = get_logger()

BACKENDS = ("none", "stdout", "webhook")


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


_SENDERS = {"stdout": _send_stdout, "webhook": _send_webhook}


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
