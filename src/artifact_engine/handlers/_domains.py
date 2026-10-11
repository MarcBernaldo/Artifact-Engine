"""The domains remote-access and tunnelling tools talk to, as one matcher (v0.7.102).

Two catalogs list them: LOLRMM's (`rmm_lolrmm.yaml`, bundled) and LOTTunnels'
(`lottunnels/tunnels.yaml`, written by `aeng setup` / `aeng update`, never
bundled -- see `core/lol_tunnels.py`). Both write domains for people, so they
are normalised here, once, for every consumer:

  - `*.ngrok.io` matches `ngrok.io` and anything under it; `*.*.x.com` is `*.x.com`;
  - a `*` anywhere else (`relay-*.net.anydesk.com`) stands for part of one label;
  - a port (`bore.pub:*`), a URL path and a trailing `*` are dropped;
  - placeholders (`user_managed`, `<operator-configured ...>`), IP addresses and
    hosts every cloud tenant shares (`github.com`, `*.amazonaws.com`) are left out:
    a match on those says nothing about the tool.

The first list to claim a domain names the tool.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

# (asset, catalog) in reading order.
LISTS = (("rmm_lolrmm.yaml", "LOLRMM"), ("lottunnels/tunnels.yaml", "LOTTunnels"))

# Hosts, and parents, that many unrelated services share.
_SHARED = {
    "github.com", "github.io", "githubusercontent.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "cloudflare.com", "api.cloudflare.com",
    "cloudflarestorage.com", "r2.cloudflarestorage.com", "amazonaws.com",
    "s3.amazonaws.com", "cloudfront.net", "windows.net", "blob.core.windows.net",
    "core.windows.net", "servicebus.windows.net", "azurewebsites.net", "googleapis.com",
    "google.com", "microsoft.com", "akamaized.net", "fastly.net", "ghcr.io",
    # suites whose remote-support product is one service among many (measured in
    # LOLRMM: mail, CRM and help-desk traffic would all match)
    "zoho.com", "zoho.eu", "zoho.in", "basecamp.com", "freshworks.com", "freshchat.com",
    "myfreshworks.com", "freshworksapi.com", "parallels.com", "nvaccess.org",
}
_LABEL = re.compile(r"[a-z0-9*_-]+")


class Matcher:
    def __init__(self) -> None:
        self.exact: dict[str, tuple] = {}
        self.suffix: dict[str, tuple] = {}
        self.globs: list[tuple[re.Pattern, tuple]] = []
        self._order = 0                 # claim order: the earliest claim wins a match

    def __len__(self) -> int:
        return len(self.exact) + len(self.suffix) + len(self.globs)

    def add(self, raw: str, tool: str, catalog: str) -> bool:
        """Add one catalog domain; False when it is left out."""
        d = str(raw or "").strip().lower()
        d = re.sub(r":(\d*|\*)$", "", d.split("/", 1)[0])
        d = d.rstrip("*").rstrip(".")
        wild = False
        while d.startswith("*."):
            d, wild = d[2:], True
        labels = d.split(".")
        if len(labels) < 2 or not all(_LABEL.fullmatch(x) for x in labels):
            return False                                # placeholder or prose
        try:
            ipaddress.ip_address(d)
            return False
        except ValueError:
            pass
        if d in _SHARED:
            return False
        self._order += 1
        what = (self._order, tool, catalog, str(raw).strip())
        if "*" in d:
            fixed = d.replace("*", "")
            if len(fixed.replace(".", "")) < 6:
                return False
            rx = re.compile(("(?:.+\\.)?" if wild else "")
                            + re.escape(d).replace(r"\*", "[a-z0-9_.-]*" if d.startswith("*")
                                                   else "[a-z0-9_-]*") + r"\Z")
            self.globs.append((rx, what))
        elif wild:
            self.suffix.setdefault(d, what)
        else:
            self.exact.setdefault(d, what)
        return True

    def match(self, host: str):
        """(tool, catalog, pattern) for a host name, or None."""
        h = str(host or "").strip().lower().rstrip(".")
        if not h or "." not in h:
            return None
        hits = [self.exact.get(h)]
        labels = h.split(".")
        hits += [self.suffix.get(".".join(labels[i:])) for i in range(len(labels) - 1)]
        hits += [what for rx, what in self.globs if rx.match(h)]
        hits = [x for x in hits if x]
        return min(hits)[1:] if hits else None


def load(assets: Path) -> Matcher:
    m = Matcher()
    for name, catalog in LISTS:
        try:
            data = yaml.safe_load((Path(assets) / name).read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        for t in data.get("tools") or []:
            for d in (t or {}).get("domains") or []:
                m.add(d, str(t.get("name") or "?"), catalog)
    return m


def host_of(url: str) -> str:
    try:
        return urlsplit(str(url or "").strip()).hostname or ""
    except ValueError:
        return ""
