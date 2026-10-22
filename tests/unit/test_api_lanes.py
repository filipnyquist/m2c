import asyncio
import time
import weakref
from concurrent.futures import ThreadPoolExecutor

from m2c.api import Api


def lanes(readers=3):
    api = Api.__new__(Api)  # only the reader lanes; no proxy state, no server
    heavy = max(1, readers // 3)
    api.pool = ThreadPoolExecutor(readers - heavy)
    api.heavy_pool = ThreadPoolExecutor(heavy)
    api.scoped_share = max(1, readers - heavy - 1)
    api._limits = weakref.WeakValueDictionary()
    return api


def test_heavy_work_never_blocks_the_interactive_lane():
    api = lanes()

    async def main():
        slow = [asyncio.create_task(api.run(time.sleep, 1.0, heavy=True)) for _ in range(3)]
        await asyncio.sleep(0.1)
        t0 = time.monotonic()
        assert await api.run(lambda: "listed") == "listed"
        assert time.monotonic() - t0 < 0.3
        await asyncio.gather(*slow)

    asyncio.run(main())


def test_a_session_token_gets_one_heavy_query_at_a_time():
    api = lanes(6)
    running, peak = [0], [0]

    def work():
        running[0] += 1
        peak[0] = max(peak[0], running[0])
        time.sleep(0.1)
        running[0] -= 1

    async def main():
        await asyncio.gather(*(api.run(work, heavy=True, scope="bob") for _ in range(4)))

    asyncio.run(main())
    assert peak[0] == 1
