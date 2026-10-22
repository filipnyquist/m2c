"""Labels and notes on flows: the one thing m2c lets its readers write.

Writes go through the writer like every row (an edit or a delete is a new version of the same id). The writer
flushes every few hundred milliseconds, so `Notes` keeps what it wrote for a minute and merges it into reads: whoever
just saved a note sees it at once. Who may write: the admin token anywhere; a session token on its own session's
flows, and only to its own notes.
"""

from __future__ import annotations

import re
import time
import uuid

from . import rows

LABEL = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")
COLORS = ("", "red", "orange", "yellow", "green", "blue", "purple", "gray")
NOTE_MAX = 16 << 10
OVERLAY_S = 60  # by then the writer has long flushed


class NoteError(ValueError):
    """A bad note (400)."""


class NoteDenied(PermissionError):
    """Not this caller's to change (403)."""


def clean(fields: dict, partial: bool = False) -> dict:
    """The writable fields of a note, checked: label (lower case, [a-z0-9_.-], 32 chars), color, note text."""
    out = {}
    if not isinstance(fields, dict):
        raise NoteError("a note is a JSON object")
    unknown = set(fields) - {"label", "color", "note"}
    if unknown:
        raise NoteError(f"unknown fields: {', '.join(sorted(unknown))}")
    if "label" in fields:
        label = fields["label"]
        if not isinstance(label, str) or (label and not LABEL.fullmatch(label.strip().lower())):
            raise NoteError("label: up to 32 of a-z 0-9 _ . - (starting with a letter or digit)")
        out["label"] = label.strip().lower()
    if "color" in fields:
        if fields["color"] not in COLORS:
            raise NoteError(f"color is one of {', '.join(c for c in COLORS if c)}")
        out["color"] = fields["color"]
    if "note" in fields:
        note = fields["note"]
        if not isinstance(note, str) or len(note.encode("utf-8", "surrogateescape")) > NOTE_MAX:
            raise NoteError(f"note: text up to {NOTE_MAX // 1024} KiB")
        out["note"] = note
    if not partial and not (out.get("label") or out.get("note", "").strip()):
        raise NoteError("a note needs a label or some text")
    return out


def view(row: dict) -> dict:
    """A stored or pending version as the API returns notes."""
    return {"id": str(row["id"]), "n": int(row["n"]), "flow_id": str(row.get("flow_id") or ""), "session": row["session"],
            "author": row["author"], "author_kind": row["author_kind"],
            "label": row.get("label", ""), "color": row.get("color", ""), "note": row.get("note", ""), "deleted": bool(row.get("deleted")),
            "created": int(row.get("created") or row["ts"]), "updated": int(row.get("updated") or row["ts"])}


def may_edit(note: dict, admin: bool, scope: str | None) -> bool:
    return admin or (note["author_kind"] == "session" and note["author"] == scope and note["session"] == scope)


class Notes:
    def __init__(self, writer, scan_id: str, enabled: bool = True):
        self.writer = writer
        self.scan_id = scan_id
        self.enabled = enabled
        self.pending: dict[str, tuple[float, dict]] = {}  # id -> (monotonic time, latest version written)

    def _expire(self) -> None:
        edge = time.monotonic() - OVERLAY_S
        for k in [k for k, (at, _) in self.pending.items() if at < edge]:
            del self.pending[k]

    def _write(self, version: dict) -> dict:
        if not self.writer.put("annotations", dict(version)):
            raise RuntimeError("the writer is full or stopped: the note was not saved")
        self.pending[str(version["id"])] = (time.monotonic(), version)
        return view(version)

    def add(self, flow: dict, fields: dict, admin: bool, scope: str | None) -> dict:
        if not self.enabled:
            raise NoteDenied("annotations are off (m2c_annotations=false)")
        if not admin and flow["session"] != scope:
            raise NoteDenied("a session token annotates its own session's flows only")
        now = rows.ms(time.time())
        return self._write({"scan_id": self.scan_id, "id": str(uuid.uuid4()), "ts": now, "created": now, "flow_id": flow["flow_id"],
                            "n": flow["n"], "session": flow["session"], "author": "admin" if admin else scope,
                            "author_kind": "admin" if admin else "session", **{"label": "", "color": "", "note": ""}, **clean(fields)})

    def change(self, current: dict, fields: dict | None, admin: bool, scope: str | None) -> dict:
        """A new version of `current` (a view): `fields` changed, or deleted when None."""
        if not self.enabled:
            raise NoteDenied("annotations are off (m2c_annotations=false)")
        if not may_edit(current, admin, scope):
            raise NoteDenied("only its author (or the admin token) changes a note")
        version = {**current, "scan_id": self.scan_id, "ts": max(rows.ms(time.time()), current["updated"] + 1)}
        if fields is None:
            version["deleted"] = True
        else:
            version.update(clean(fields, partial=True))
            if not (version["label"] or version["note"].strip()):
                raise NoteError("a note needs a label or some text; delete it instead")
        return self._write(version)

    def merge(self, stored: list[dict], keep=lambda note: True, deleted: bool = False) -> list[dict]:
        """Stored notes (views) with this process's recent writes on top; deleted ones left out unless asked."""
        self._expire()
        by_id = {x["id"]: x for x in stored}
        for nid, (_, version) in self.pending.items():
            v = view(version)
            old = by_id.get(nid)
            if old is not None:
                v["created"] = old["created"]
            if (old is None or v["updated"] >= old["updated"]) and keep(v):
                by_id[nid] = v
        out = [x for x in by_id.values() if deleted or not x["deleted"]]
        return sorted(out, key=lambda x: (x["n"], x["created"]))
