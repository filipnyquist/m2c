import pytest

from m2c.notes import NoteDenied, NoteError, Notes, clean, may_edit


class FakeWriter:
    def __init__(self, ok=True):
        self.rows, self.ok = [], ok

    def put(self, table, row):
        self.rows.append((table, row))
        return self.ok


FLOW = {"n": 7, "flow_id": "6f1c1c55-0000-4000-8000-000000000001", "session": "s1"}


@pytest.mark.parametrize("fields", [{}, {"label": "Not Ok!"}, {"color": "pink", "label": "x"}, {"note": "x" * (17 << 10)},
                                    {"label": "x", "author": "me"}, {"label": 5}, {"note": "   "}])
def test_bad_notes(fields):
    with pytest.raises(NoteError):
        clean(fields)


def test_labels_are_normalized():
    assert clean({"label": " Auth-Bypass "}) == {"label": "auth-bypass"}


def test_a_session_token_writes_on_its_own_flows_and_edits_its_own_notes():
    notes = Notes(FakeWriter(), "scan1")
    mine = notes.add(FLOW, {"label": "vuln"}, admin=False, scope="s1")
    assert (mine["author"], mine["author_kind"], mine["session"]) == ("s1", "session", "s1")
    with pytest.raises(NoteDenied):
        notes.add(FLOW, {"label": "x"}, admin=False, scope="s2")
    by_admin = notes.add(FLOW, {"note": "seen"}, admin=True, scope=None)
    assert not may_edit(by_admin, admin=False, scope="s1") and may_edit(mine, admin=False, scope="s1")
    with pytest.raises(NoteDenied):
        notes.change(by_admin, {"note": "mine now"}, admin=False, scope="s1")
    edited = notes.change(mine, {"note": "token reuse"}, admin=False, scope="s1")
    assert edited["id"] == mine["id"] and edited["label"] == "vuln" and edited["note"] == "token reuse" and edited["updated"] > mine["updated"] - 1
    with pytest.raises(NoteError):
        notes.change(edited, {"label": "", "note": ""}, admin=False, scope="s1")


def test_reads_see_writes_before_the_writer_flushes():
    notes = Notes(FakeWriter(), "scan1")
    a = notes.add(FLOW, {"label": "a"}, admin=True, scope=None)
    b = notes.add({**FLOW, "n": 8}, {"label": "b"}, admin=True, scope=None)
    assert [x["label"] for x in notes.merge([], lambda v: v["n"] == 7)] == ["a"]
    stored = [{**a, "created": a["created"] - 5}]  # the database has an older copy of a
    notes.change(a, None, admin=True, scope=None)  # then a is deleted
    assert [x["id"] for x in notes.merge(stored)] == [b["id"]]  # the deletion wins over the stored copy
    assert [x["deleted"] for x in notes.merge(stored, deleted=True) if x["id"] == a["id"]] == [True]


def test_a_full_writer_is_an_error_and_off_means_off():
    with pytest.raises(RuntimeError):
        Notes(FakeWriter(ok=False), "scan1").add(FLOW, {"label": "a"}, admin=True, scope=None)
    with pytest.raises(NoteDenied):
        Notes(FakeWriter(), "scan1", enabled=False).add(FLOW, {"label": "a"}, admin=True, scope=None)
