"""Who sent a request: proxy credentials, session tokens, header overrides and the User-Agent guess.

    username = <session>.<tool>[.<call>]
    password = v1.<exp>.<mac>       (auth "token": exp base36 unix seconds or 0, mac = HMAC of the session)
             | <shared secret>      (auth "shared")
             | anything             (auth "open"; a username without a dot means session=username, tool=password)

Only RFC 3986 unreserved characters are allowed, so no client has to percent-encode anything. The MAC binds the
session only: inside its own session an agent may name any tool or call, but it cannot write into another session.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass

SESSION = re.compile(r"[A-Za-z0-9_-]{1,64}")
TOOL = re.compile(r"[A-Za-z0-9_-]{1,48}")
CALL = re.compile(r"[A-Za-z0-9._~-]{1,96}")
MODES = ("token", "shared", "open")
USER_CAP = 256
HEADER_TOOL = "x-m2c-tool"
HEADER_CALL = "x-m2c-call"
HEADER_TAG = "x-m2c-tag"
OVERRIDE_HEADERS = (HEADER_TOOL, HEADER_CALL, HEADER_TAG)


@dataclass(frozen=True)
class Identity:
    session: str
    tool: str
    call: str = ""
    user: str = ""
    source: str = "request"  # connect | request | socks5 | header


class AuthError(Exception):
    """Bad credentials; str(e) is a short machine reason: missing, bad_format, bad_mac, expired, bad_secret."""


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def _b36(n: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while True:
        n, r = divmod(n, 36)
        out = digits[r] + out
        if not n:
            return out


def _mac(secret: str, session: str, exp: str) -> str:
    raw = hmac.new(secret.encode(), f"m2c|v1|{session}|{exp}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")[:22]


def mint(secret: str, session: str, ttl: float | None = None, now: float | None = None) -> str:
    """Token for `session`; ttl in seconds, None for no expiry."""
    if not SESSION.fullmatch(session):
        raise ValueError(f"session must match {SESSION.pattern}")
    exp = "0" if not ttl else _b36(int((now or time.time()) + ttl))
    return f"v1.{exp}.{_mac(secret, session, exp)}"


def check_token(secrets_: list[str], session: str, token: str, now: float | None = None) -> None:
    if not token.isascii():  # compare_digest raises TypeError on non-ASCII str; never let that escape
        raise AuthError("bad_format")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "v1" or not parts[1] or not parts[2]:
        raise AuthError("bad_format")
    _, exp, mac = parts
    if not any(hmac.compare_digest(_mac(s, session, exp).encode(), mac.encode()) for s in secrets_):
        raise AuthError("bad_mac")
    if exp != "0":
        try:
            expires = int(exp, 36)
        except ValueError:
            raise AuthError("bad_format") from None
        if expires < (now or time.time()):
            raise AuthError("expired")


def parse_user(user: str) -> tuple[str, str, str]:
    """(session, tool, call) from `<session>.<tool>[.<call>]`."""
    parts = user.split(".", 2)
    if len(parts) < 2:
        raise AuthError("bad_format")
    session, tool, call = parts[0], parts[1].lower(), parts[2] if len(parts) > 2 else ""
    if not SESSION.fullmatch(session) or not TOOL.fullmatch(tool) or (call and not CALL.fullmatch(call)):
        raise AuthError("bad_format")
    return session, tool, call


class Authenticator:
    """Validates proxy credentials. Verified pairs are cached; token expiry is re-checked on every hit."""

    def __init__(self, mode: str, secrets_: list[str] | None = None, cache_size: int = 4096):
        if mode not in MODES:
            raise ValueError(f"auth mode must be one of {MODES}")
        self.mode = mode
        self.secrets = [s for s in (secrets_ or []) if s]
        if mode in ("token", "shared") and not self.secrets:
            raise ValueError(f"auth mode {mode!r} needs a secret")
        self.cache: OrderedDict[tuple[str, str], tuple[Identity, str]] = OrderedDict()
        self.cache_size = cache_size

    def check(self, user: str | None, password: str | None, source: str = "request") -> Identity:
        """The sender's identity, or AuthError. Never raises anything else (callers fail closed on AuthError)."""
        try:
            return self._check(user, password, source)
        except AuthError:
            raise
        except Exception as e:  # noqa: BLE001 - malformed input must be a rejection, not a crash that lets it through
            raise AuthError("bad_format") from e

    def _check(self, user: str | None, password: str | None, source: str) -> Identity:
        if not user:
            raise AuthError("missing")
        key = (user, password or "")
        hit = self.cache.get(key)
        if hit is not None:
            self.cache.move_to_end(key)
            ident, exp = hit
            if exp and int(exp, 36) < time.time():
                del self.cache[key]
                raise AuthError("expired")
            return ident if ident.source == source else Identity(ident.session, ident.tool, ident.call, ident.user, source)
        ident = self._validate(user, password or "", source)
        exp = ""
        if self.mode == "token":
            exp = (password or "").split(".")[1]
            exp = "" if exp == "0" else exp
        self.cache[key] = (ident, exp)
        if len(self.cache) > self.cache_size:
            self.cache.popitem(last=False)
        return ident

    def _validate(self, user: str, password: str, source: str) -> Identity:
        if len(user) > USER_CAP:
            raise AuthError("bad_format")
        if self.mode == "open" and "." not in user:
            if not SESSION.fullmatch(user):
                raise AuthError("bad_format")
            tool = password.lower() if TOOL.fullmatch(password or "") else "unknown"
            return Identity(user, tool, "", user, source)
        session, tool, call = parse_user(user)
        if self.mode == "token":
            check_token(self.secrets, session, password)
        elif self.mode == "shared":
            if not any(hmac.compare_digest(password.encode("utf-8", "surrogateescape"), s.encode()) for s in self.secrets):
                raise AuthError("bad_secret")
        return Identity(session, tool, call, user, source)


def override(ident: Identity, tool: str | None, call: str | None) -> Identity:
    """Apply x-m2c-tool / x-m2c-call. Invalid values are ignored; the session never changes."""
    tool = tool.strip().lower() if tool else ""
    call = call.strip() if call else ""
    new_tool = tool if tool and TOOL.fullmatch(tool) else ident.tool
    new_call = call if call and CALL.fullmatch(call) else ident.call
    if (new_tool, new_call) == (ident.tool, ident.call):
        return ident
    return Identity(ident.session, new_tool, new_call, ident.user, "header")


def clean_tag(tag: str | None) -> str:
    if not tag:
        return ""
    return "".join(ch for ch in tag if ch.isprintable())[:128]


UA_TOOLS: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.I), name)
    for p, name in [
        (r"^curl/", "curl"),
        (r"^Wget/", "wget"),
        (r"sqlmap", "sqlmap"),
        (r"nuclei", "nuclei"),
        (r"ffuf", "ffuf"),
        (r"Fuzz Faster U Fool", "ffuf"),
        (r"gobuster", "gobuster"),
        (r"feroxbuster", "feroxbuster"),
        (r"nikto", "nikto"),
        (r"Nmap", "nmap"),
        (r"^git/", "git"),
        (r"python-requests", "python-requests"),
        (r"python-httpx", "python-httpx"),
        (r"aiohttp", "python-aiohttp"),
        (r"python-urllib|Python-urllib", "python-urllib"),
        (r"^node|undici", "node"),
        (r"axios", "node-axios"),
        (r"Go-http-client", "go"),
        (r"okhttp", "okhttp"),
        (r"HeadlessChrome", "headless-chrome"),
        (r"Playwright", "playwright"),
        (r"Firefox/", "firefox"),
        (r"Chrome/", "chrome"),
    ]
]


def ua_tool(user_agent: str | None) -> str:
    """A guess from the User-Agent, for forensics only; never used for attribution."""
    if not user_agent:
        return ""
    for pattern, name in UA_TOOLS:
        if pattern.search(user_agent):
            return name
    return "other"
