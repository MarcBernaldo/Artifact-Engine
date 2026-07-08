"""Web-attack payload signatures for the `huntweb` hunt.

Each rule is a (category, compiled-regex) pair. Patterns are matched against a
*decoded* haystack (see _webcommon.decode: URL %XX + double-encoding + \\xNN +
lowercased), so an encoded payload (`%2e%2e%2f`, `%3cscript`) hits the same rule
as its plaintext form.

Tuned against real UAC access logs (jetpack xmlrpc, php file-managers, scanner
noise) to fire on actual injection content, not on path reputation or status
code -- recon (404s to sensitive paths) is intentionally NOT a category.

`classify()` returns the single most-decisive category (priority order below)
plus the full set of categories the request matched.
"""

from __future__ import annotations

import re

# Cheap raw-line pre-filter: only lines containing one of these substrings are
# decoded and run through the full ruleset (the other ~99% are skipped). Covers
# the plaintext tokens and the common single-encoded forms; fully double-encoded
# payloads are the known gap (rare in practice).
_PREFILTER = re.compile(
    r"union|select|sleep\(|benchmark|information_schema|group_concat|extractvalue|updatexml|waitfor|"
    r"<script|%3cscript|onerror|onload|onmouseover|javascript:|<svg|<iframe|"
    r"\$\{|jndi|%24%7b|"
    r"php://|file://|data://|expect://|phar://|%3a%2f%2f|"
    r"/etc/passwd|/etc/shadow|passwd|proc/self|win\.ini|boot\.ini|"
    r"\.\./|\.\.\\|%2e%2e|%00|"
    r"shell_exec|passthru|system\(|popen|proc_open|pcntl_exec|call_user_func|invokefunction|think|"
    r"wget|curl|chmod|/bin/|bash|/dev/tcp|nc -e|ncat|phpinfo|allow_url_include|auto_prepend|"
    r"c99|r57|wso|b374k|weevely|eval\(|assert\(|base64_decode|\$_(get|post|request|cookie)",
    re.IGNORECASE,
)

# (category, regex) -- regex applied to the decoded, lowercased haystack.
_RULES: list[tuple[str, re.Pattern]] = [
    ("log4shell", re.compile(r"\$\{jndi:|jndi:(ldap|ldaps|rmi|dns|iiop|nis|corba)|"
                             r"\$\{(lower|upper|env|sys|java|date|base64|main):")),
    ("cmdi", re.compile(
        r"\b(shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(|"
        r"call_user_func(_array)?|invokefunction|think\\?app|"      # ThinkPHP RCE
        r";\s*(wget|curl|bash|sh|nc|ncat|python|perl|id|whoami|uname|cat)\b|"
        r"\|\s*(wget|curl|bash|sh|nc|ncat)\b|"
        r"&&\s*(wget|curl|chmod|sh|bash|cd)\b|"
        r"\$\([^)]+\)|`[^`]+`|"                                     # $(...) / backticks
        r"\bchmod\s*\+x\b|/bin/(ba)?sh\b|bash\s+-i|nc\s+-e|>?/dev/tcp/|"
        r"\b(wget|curl)\s+https?://|\$\{ifs\}|"
        r"phpinfo\s*\(|allow_url_include|auto_prepend_file")),
    ("webshell", re.compile(
        r"\b(c99|r57|wso|b374k|weevely|china[\s_-]?chopper)\b|"
        r"(eval|assert|system|passthru|shell_exec)\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_)|"
        r"\$_(get|post|request|cookie)\s*\[[^\]]*\]\s*\(|"          # $_GET[x](...) dynamic call
        r"\.(phtml|phar|php[3457])\b")),
    ("sqli", re.compile(
        r"union(\s+all)?\s+select|"
        r"\bor\s+1\s*=\s*1\b|\bor\s+'1'\s*=\s*'1|'\s*or\s*'1'\s*=\s*'1|"
        r"\b(sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay|"
        r"information_schema|group_concat\s*\(|extractvalue\s*\(|updatexml\s*\(|"
        r"\binto\s+(outfile|dumpfile)\b|/\*!\d")),
    ("xss", re.compile(
        r"<\s*script|</\s*script|<\s*svg|<\s*iframe|<\s*img[^>]+onerror|<\s*body[^>]+onload|"
        r"on(error|load|mouseover|focus|click|animationstart)\s*=|"
        r"javascript:|vbscript:|data:text/html|"
        r"document\.cookie|string\.fromcharcode|alert\s*\(|prompt\s*\(")),
    ("lfi", re.compile(
        r"(php|file|data|expect|phar|zip|glob|compress\.\w+)://|"
        r"/etc/(passwd|shadow|group|gshadow)\b|"
        r"/proc/self/(environ|cmdline|maps|status)|"
        r"\bwin\.ini\b|\bboot\.ini\b|/windows/(win\.ini|system32)")),
    ("traversal", re.compile(r"\.\.(/|\\)|\.\.%2f|\.\.%5c|%00")),
]

# When several categories match, keep this one as the headline `flag`.
_PRIORITY = ["log4shell", "cmdi", "webshell", "sqli", "lfi", "traversal", "xss"]
_RANK = {c: i for i, c in enumerate(_PRIORITY)}


def prefilter(raw_pq: str) -> bool:
    """True if a raw (still-encoded) path+query is worth decoding + classifying.
    Callers pass path+query only -- the ruleset never matches UA/referer, so
    scanning them just costs bytes and false-hits on benign tool UAs."""
    return _PREFILTER.search(raw_pq) is not None


def classify(haystack: str) -> tuple[str, str]:
    """(primary_category, all_categories) for a decoded request, or ('', '').

    `all_categories` is a '+'-joined list (priority order) for context.
    """
    hits = [cat for cat, rx in _RULES if rx.search(haystack)]
    if not hits:
        return "", ""
    hits = sorted(set(hits), key=lambda c: _RANK[c])
    return hits[0], "+".join(hits)
