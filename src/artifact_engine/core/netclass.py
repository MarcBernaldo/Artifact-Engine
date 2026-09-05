"""Which side of the perimeter an address is on.

`ipaddress.is_global` answers "is this routable on the internet", and for most
estates that is the same question as "did this come from outside". For the ones
it is not -- universities, hospitals, large enterprises holding their own
publicly-routable allocation -- it is exactly backwards: every ordinary
file-share access between two of their own hosts is a globally-routable address
talking to another one, generic Sigma rules read that as "external logon from a
public IP", and the analyst is handed hundreds of high-severity rows that are all
noise. Triaging those by hand, per host, is pure waste, and the real cost is not
the hours: it is that the rule class starts being ignored.

So the org declares its own ranges once, in `config.yaml`:

    internal_networks:
      - 10.0.0.0/8            # harmless to state, already private
      - 203.0.113.0/24        # the part that matters: routable, and ours

and every consumer asks this module instead of asking `ipaddress` directly.

TWO THINGS THIS DELIBERATELY DOES NOT DO. It never deletes or hides anything --
a declared address is RECLASSIFIED and says so, because "we own that range" is a
claim about ownership, not about innocence, and an attacker who reaches a host
inside the range is exactly the case where a suppressed row would be the one that
mattered. And it never guesses: a range it cannot parse is reported, not dropped,
because a typo that silently matches nothing looks identical to a rule that is
working.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from artifact_engine.logging_setup import get_logger

log = get_logger()

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network
_Addr = ipaddress.IPv4Address | ipaddress.IPv6Address

# Scopes, most specific first. `""` means the value was not an address at all --
# a host name, a SID, an empty cell -- which is a different answer from "private"
# and must not be confused with it.
INTERNAL = "internal"
PRIVATE = "private"
PUBLIC = "public"


@dataclass(frozen=True)
class NetClass:
    """The declared internal ranges, and what they say about an address."""

    networks: tuple[_Net, ...] = ()
    # Entries that could not be read, kept so a caller can report them. A silently
    # dropped range is a rule the analyst believes is running and is not.
    rejected: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.networks)

    def contains(self, addr: _Addr | str) -> bool:
        """Whether this address falls in a declared range."""
        ip = addr if isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
            else _as_ip(str(addr))
        if ip is None:
            return False
        # No version guard: `ipaddress` answers False across families rather
        # than raising, so a v4 address is simply never in a v6 range.
        return any(ip in n for n in self.networks)

    def scope(self, value: str) -> str:
        """`internal` / `private` / `public`, or "" when it is not an address.

        A declared range wins over everything, including over `private`: an org
        that lists `10.0.0.0/8` has said something true and should see it
        reflected, and the alternative -- answering `private` for a range the
        analyst explicitly declared -- reads as if the declaration was ignored.
        """
        ip = _as_ip(value)
        if ip is None:
            return ""
        if self.contains(ip):
            return INTERNAL
        return PUBLIC if ip.is_global else PRIVATE

    def is_public(self, value: str) -> bool:
        """Globally routable AND not declared as the organisation's own."""
        return self.scope(value) == PUBLIC


EMPTY = NetClass()


def _as_ip(value: str) -> _Addr | None:
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def parse(entries) -> NetClass:
    """A configured list of CIDRs (or bare addresses) as a NetClass.

    Accepts a list, or one string with commas or whitespace between entries,
    because both are how the value gets written by hand. Host bits are masked off
    rather than refused -- `203.0.113.9/24` is what somebody writes when they mean
    the network -- but the interpretation is logged, since a `/24` that was meant
    to be a `/16` is a real mistake and a silent mask hides it.
    """
    networks: list[_Net] = []
    rejected: list[str] = []
    for raw in _as_entries(entries):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as e:
            log.warning(f"[!] internal_networks: ignoring {text!r} ({e})")
            rejected.append(text)
            continue
        if "/" in text and str(net) != text:
            log.info(f"[+] internal_networks: {text} read as {net}")
        networks.append(net)
    return NetClass(tuple(networks), tuple(rejected))


def _as_entries(entries) -> list[str]:
    if entries is None:
        return []
    if isinstance(entries, str):
        return [p for p in entries.replace(",", " ").split() if p]
    if isinstance(entries, (list, tuple, set)):
        return [str(e) for e in entries]
    return [str(entries)]


def describe(nc: NetClass) -> str:
    """One line for a run summary, or "" when nothing was declared."""
    if not nc.networks and not nc.rejected:
        return ""
    parts = [f"{len(nc.networks)} internal range(s) declared"]
    if nc.rejected:
        parts.append(f"{len(nc.rejected)} unreadable and IGNORED: "
                     + ", ".join(nc.rejected[:5]))
    return "; ".join(parts)
