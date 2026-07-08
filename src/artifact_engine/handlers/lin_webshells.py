"""Handler: webshell/backdoor scan of the web root(s). Output: webshells.csv

Runs only when the acquisition contains a web server document root
(/var/www, /srv/www, nginx, ~/public_html, ...); otherwise it skips. Scans
server-side scripts (PHP/JSP/ASP/CGI) and .htaccess for the patterns that
distinguish a backdoor from normal application code.

The core heuristic is input-flowing-straight-into-an-exec-sink
(e.g. eval($_POST[...]), system($_GET[...]), eval(base64_decode(...))): real
frameworks use eval/base64/system, but almost never with a request superglobal
as the direct argument, which keeps false positives low even on large apps.
This is a triage signal, not a verdict.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import read_text, root, write_csv

_WEBROOTS = ("var/www", "srv/www", "usr/share/nginx", "srv/http",
             "usr/local/apache2/htdocs", "opt/lampp/htdocs")

# Server-side script types worth scanning (static assets are skipped).
_EXTS = {".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".inc",
         ".jsp", ".jspx", ".jspf", ".asp", ".aspx", ".ashx", ".asmx",
         ".cfm", ".pl", ".cgi"}

_MAX_BYTES = 3_000_000   # webshells are tiny; skip large data/asset files

# (regex, label) -- high-signal webshell markers.
_PATTERNS = [
    (re.compile(
        r"(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)"
        r"\s*\(\s*(?:@?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate"
        r"|gzuncompress|gzdecode|str_rot13)", re.I), "input_to_exec"),
    (re.compile(r"@?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(", re.I),
     "dynamic_call_on_input"),
    (re.compile(r"\bpreg_replace\s*\([^)]*?/[a-z]*e[a-z]*['\"]", re.I), "preg_replace_e"),
    (re.compile(r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(",), "jsp_exec"),
    (re.compile(r"\b(?:eval|execute)\s*\(\s*request", re.I), "asp_request_eval"),
    (re.compile(r"\bWScript\.Shell\b", re.I), "wscript_shell"),
    (re.compile(r"['\"][A-Za-z0-9+/]{256,}={0,2}['\"]"), "long_base64_blob"),
]

# .htaccess directives that turn a directory into an execution/backdoor vector.
_HTACCESS = re.compile(
    r"auto_(?:pre|ap)pend_file|SetHandler[^\n]*php|AddType[^\n]*php|AddHandler[^\n]*php"
    r"|php_value\s+auto_", re.I)


def _rel(base: Path, f: Path) -> str:
    try:
        return f.relative_to(base).as_posix()
    except ValueError:
        return f.name


def _web_roots(base: Path) -> list[Path]:
    cands = [base / p for p in _WEBROOTS]
    home = base / "home"
    if home.is_dir():
        cands += [h / "public_html" for h in home.iterdir() if h.is_dir()]
    cands.append(base / "root" / "public_html")
    existing = [d for d in cands if d.is_dir()]
    # Drop a root nested under another (var/www/html lives under var/www).
    roots: list[Path] = []
    for d in sorted(existing, key=lambda p: len(p.parts)):
        if not any(d.is_relative_to(r) for r in roots):
            roots.append(d)
    return roots


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start: end if end != -1 else len(text)].strip()[:160]


def _size_kb(f: Path) -> int:
    try:
        return max(1, f.stat().st_size // 1024)
    except OSError:
        return 0


def _scan_script(f: Path, base: Path, rows: list[list]) -> None:
    try:
        if f.stat().st_size > _MAX_BYTES:
            return
    except OSError:
        return
    text = read_text(f)
    if not text:
        return
    labels: list[str] = []
    snippet = ""
    for rx, label in _PATTERNS:
        m = rx.search(text)
        if m:
            labels.append(label)
            if not snippet:
                snippet = _line_at(text, m.start())
    if labels:
        rows.append([_rel(base, f), ",".join(dict.fromkeys(labels)), snippet, _size_kb(f)])


def _scan_htaccess(f: Path, base: Path, rows: list[list]) -> None:
    for ln in read_text(f).splitlines():
        s = ln.strip()
        if s and not s.startswith("#") and _HTACCESS.search(s):
            rows.append([_rel(base, f), "htaccess_handler", s[:160], _size_kb(f)])


def run(ctx) -> None:
    base = root(ctx.evidence)
    roots = _web_roots(base)
    if not roots:
        raise HandlerSkip("no web root present")

    rows: list[list] = []
    for r in roots:
        for f in r.rglob("*"):
            if not f.is_file():
                continue
            if f.name == ".htaccess":
                _scan_htaccess(f, base, rows)
            elif f.suffix.lower() in _EXTS:
                _scan_script(f, base, rows)

    rows.sort(key=lambda r: r[0])
    write_csv(ctx.out, "webshells.csv",
              ["path", "indicators", "snippet", "size_kb"], rows)
