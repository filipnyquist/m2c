"""Claude Code hooks: tag the traffic of each Bash call with the call's id, and nothing else.

- SessionStart writes CLAUDE_ENV_FILE, which Claude Code runs as shell code before each Bash command. Besides the
  usual proxy variables it builds the proxy URL from a small local file holding the current call's id, so every
  request a Bash command makes carries `<session>.bash.<tool_use_id>` (the call part of the proxy username).
- PreToolUse (Bash only) writes that file.

Nothing is sent anywhere and nothing about the call itself is recorded: m2c records only what goes through the
proxy, so a call is visible through its traffic alone (the timeline groups flows by call id). Hooks fail open: they
never block a tool call; a problem goes to <data>/hooks.log. With parallel Bash calls the file holds the latest
call's id, so a flow can carry a sibling call's id.
"""

from __future__ import annotations

import os
import re
import shlex
import tempfile
import time
from pathlib import Path

CALL_ID = re.compile(r"[A-Za-z0-9._~-]{1,96}")  # what the proxy username's call part allows (identity.CALL)


def session_id(raw) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "-", str(raw or "session"))[:64].strip("-")
    return cleaned or "session"


def run_dir() -> Path:
    """A private directory for the current-call files: under $XDG_RUNTIME_DIR, else the temp directory."""
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    d = Path(base) / (f"m2c-{os.getuid()}" if not os.environ.get("XDG_RUNTIME_DIR") else "m2c")
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if d.stat().st_uid != os.getuid():
        raise PermissionError(f"{d} belongs to another user")
    return d


def call_file(session: str) -> Path:
    return run_dir() / f"{session}.call"


def env_snippet(env: dict[str, str], session: str, tool: str, extra: dict[str, str]) -> str:
    """Shell for CLAUDE_ENV_FILE: the static variables, then the proxy URLs built from the current call's id."""
    user = f"{session}.{tool}"
    url = env.get("HTTP_PROXY", "")
    dynamic = [k for k, v in env.items() if v == url and f"//{user}:" in v]
    template = url.replace(f"//{user}:", "//${m2c_u}:")
    if not dynamic or not re.fullmatch(r"[A-Za-z0-9.:/@_~%+${}-]*", template):
        dynamic, template = [], ""  # nothing that can go in double quotes safely: static URLs only
    lines = ["# m2c: the proxy for this session's tools (see `m2c hooks claude-code`)"]
    lines += [f"export {k}={shlex.quote(v)}" for k, v in {**env, **extra}.items() if k not in dynamic]
    if dynamic:
        cf = shlex.quote(str(call_file(session)))
        lines += [
            f'm2c_c=; [ -r {cf} ] && IFS= read -r m2c_c < {cf}',
            f'case "$m2c_c" in ""|*[!A-Za-z0-9._~-]*) m2c_u={shlex.quote(user)} ;; *) m2c_u="{user}.$m2c_c" ;; esac',
            "export " + " ".join(f'{k}="{template}"' for k in dynamic),
            "unset m2c_c m2c_u",
        ]
    return "\n".join(lines) + "\n"


def mark_call(event: dict) -> None:
    """PreToolUse: a Bash call starts; its commands' requests carry its id from now on."""
    if event.get("tool_name") != "Bash":
        return
    call_id = event.get("tool_use_id")
    if not isinstance(call_id, str) or not CALL_ID.fullmatch(call_id):
        return
    path = call_file(session_id(event.get("session_id")))
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(call_id)
    os.replace(tmp, path)


def log_problem(data: Path, what: str) -> None:
    try:
        with open(data / "hooks.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {what}\n")
    except OSError:
        pass
