import asyncio

from m2c.live import CHILDREN_PER_FLOW, PREVIEW_BYTES, LiveFeed


def flow(n, session="s"):
    return {"n": n, "session": session}


def test_flow_end_survives_a_full_queue():
    async def main():
        live = LiveFeed()
        live.publish_open(flow(7))
        sub = live.subscribe_flow(7)
        for i in range(2500):  # a burst while the handler is blocked on a slow client
            live.publish_child(7, "ws", {"seq": i + 1, "content": b"x"})
        live.publish(flow(7))
        assert sub.ended == flow(7) and sub.wake.is_set()
        assert len(sub.take()) == 2000 and sub.lost == 500
        assert 7 not in live.flow_subscribers

    asyncio.run(main())


def test_flow_subscriber_is_bounded_in_bytes():
    async def main():
        live = LiveFeed()
        live.publish_open(flow(1))
        sub = live.subscribe_flow(1)
        for i in range(100):
            live.publish_child(1, "ws", {"seq": i + 1, "content": b"x" * (256 << 10)})
        assert len(sub.items) < 70 and sub.lost > 30 and sub.bytes <= sub.max_bytes

    asyncio.run(main())


def test_children_ring_keeps_previews_only():
    live = LiveFeed()
    live.publish_open(flow(3))
    big = {"seq": 1, "content": b"y" * (256 << 10), "truncated": False}
    live.publish_child(3, "ws", big)
    live.publish_child(3, "sse", {"seq": 2, "data": "z" * 70_000})
    live.publish_child(3, "ws", {"seq": 3, "content": b"small"})
    (_, ws), (_, sse), (_, small) = live.children[3]
    assert len(ws["content"]) == PREVIEW_BYTES and ws["truncated"] and ws["_preview"]
    assert len(sse["data"]) == PREVIEW_BYTES and sse["_preview"]
    assert small["content"] == b"small" and "_preview" not in small
    assert len(big["content"]) == 256 << 10  # the writer's row is untouched


def test_tail_reads_the_ring_from_its_cursor():
    async def main():
        live = LiveFeed(size=100)
        sub = live.subscribe(lambda s: s["session"] == "a")
        cursor = live.seq
        for n in range(1, 4):
            live.publish(flow(n, "b"))
        assert not sub.wake.is_set()  # nothing matching
        live.publish(flow(4, "a"))
        assert sub.wake.is_set()
        items, missed = live.since(cursor)
        assert [i["n"] for _, i in items] == [1, 2, 3, 4] and missed == 0
        # finish order, not n order: a slow flow with a smaller n still comes after the cursor
        cursor = live.seq
        live.publish(flow(2_000))
        live.publish(flow(5))
        assert [i["n"] for _, i in live.since(cursor)[0]] == [2_000, 5]

    asyncio.run(main())


def test_since_reports_what_the_ring_lost():
    live = LiveFeed(size=10)
    for n in range(1, 26):
        live.publish(flow(n))
    items, missed = live.since(5)
    assert missed == 10 and [i["n"] for _, i in items] == list(range(16, 26))
    assert live.since(live.seq) == ([], 0)
    assert 1 not in live.by_n and 25 in live.by_n


def test_open_queue_skips_db_tails():
    async def main():
        live = LiveFeed()
        sub = live.subscribe(lambda s: True, opens=False)
        live.publish_open(flow(1))
        assert not sub.items
        live.publish(flow(1))
        assert sub.wake.is_set()

    asyncio.run(main())


def test_recent_returns_seq():
    live = LiveFeed()
    for n in range(1, 6):
        live.publish(flow(n, "a" if n % 2 else "b"))
    assert live.recent(lambda s: s["session"] == "a", 2) == [(3, flow(3, "a")), (5, flow(5, "a"))]


def test_children_previews_share_one_byte_budget():
    live = LiveFeed()
    live.children_max_bytes = 100 * (PREVIEW_BYTES + 200)
    for n in range(1, 11):  # ten chatty open WebSockets with big messages
        live.publish_open(flow(n))
        for i in range(50):
            live.publish_child(n, "ws", {"seq": i + 1, "content": b"x" * (256 << 10)})
    held = sum(len(d) for d in live.children.values())
    assert live.children_bytes <= live.children_max_bytes and held <= 100
    assert live.children_bytes == sum(200 + len(r["content"]) for d in live.children.values() for _, r in d)
    assert all(len(live.children[n]) >= 5 for n in range(1, 11))  # a fair share each, early flows do not hog it
    assert [r["seq"] for _, r in live.children[10]][-1] == 50  # the newest stay
    for n in range(1, 11):
        live.publish(flow(n))
    assert live.children == {} and live.children_bytes == 0


def test_children_capped_per_flow_and_not_kept_after_finish():
    live = LiveFeed()
    live.publish_open(flow(1))
    for i in range(300):
        live.publish_child(1, "sse", {"seq": i + 1, "data": "e"})
    assert len(live.children[1]) == CHILDREN_PER_FLOW and live.children[1][0][1]["seq"] == 101
    live.publish(flow(1))
    live.publish_child(1, "sse", {"seq": 301, "data": "late"})  # after the end: nothing would ever free it
    assert 1 not in live.children and live.children_bytes == 0
