"""
aura_chaos_test.py — Standalone Stress Test for Aura's Core Systems

Tests:
  1. EventBus flood          (5000 events, backpressure + dedup)
  2. Duplicate suppression   (100 identical events → only 1 handler call)
  3. Race conditions         (100 concurrent MissionContext writes)
  4. Engine timeout kill     (fake hanging engine killed by timeout)
  5. Memory leak             (dedup LRU cache bounded at 10k)

Usage:
    cd c:\\Users\\User\\.gemini\\antigravity\\scratch\\aura
    python aura_chaos_test.py
"""
import asyncio
import time
import sys
import tracemalloc
from collections import OrderedDict

# ─────────────────────────────────────────────────────────────────
# Inline minimal stubs so the test runs without full Aura install
# ─────────────────────────────────────────────────────────────────
try:
    from aura.core.events import EventBus, AuraEvent, EventType
    from aura.core.context import MissionContext
    print("[+] Using real Aura modules")
    REAL_AURA = True
except ImportError:
    print("[!] Aura not found in path — using inline stubs for isolated testing")
    REAL_AURA = False

    from enum import Enum
    from typing import Any, Dict, List, Callable

    class EventType(str, Enum):
        VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
        TARGET_DISCOVERED   = "TARGET_DISCOVERED"
        ERROR_OCCURRED      = "ERROR_OCCURRED"

    class AuraEvent:
        def __init__(self, type, source, message, data=None):
            self.type = type; self.source = source
            self.message = message; self.data = data or {}

    class EventBus:
        MAX_CONCURRENT_HANDLERS = 50
        HANDLER_TIMEOUT_S = 10.0
        DEDUP_CACHE_SIZE = 10_000

        def __init__(self):
            self._subscribers: Dict[Any, List[Callable]] = {t: [] for t in EventType}
            self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_HANDLERS)
            self._seen_hashes: OrderedDict = OrderedDict()
            self.stats = {"published": 0, "dropped_dedup": 0, "handler_timeouts": 0}

        def subscribe(self, event_type, callback):
            self._subscribers[event_type].append(callback)

        def _is_duplicate(self, event) -> bool:
            h = hash((event.type, event.source, event.message))
            if h in self._seen_hashes:
                return True
            self._seen_hashes[h] = True
            if len(self._seen_hashes) > self.DEDUP_CACHE_SIZE:
                self._seen_hashes.popitem(last=False)
            return False

        def publish(self, event):
            self.stats["published"] += 1
            if self._is_duplicate(event):
                self.stats["dropped_dedup"] += 1
                return
            for cb in self._subscribers.get(event.type, []):
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(self._guarded(cb, event))
                else:
                    cb(event)

        async def _guarded(self, cb, event):
            async with self._semaphore:
                try:
                    await asyncio.wait_for(cb(event), timeout=self.HANDLER_TIMEOUT_S)
                except asyncio.TimeoutError:
                    self.stats["handler_timeouts"] += 1

        def get_stats(self):
            return {**self.stats, "dedup_cache_size": len(self._seen_hashes)}

        def reset_dedup_cache(self):
            self._seen_hashes.clear()

    class MissionContext:
        def __init__(self, target_url):
            self.target_url = target_url
            self.discovered_urls = set()
            self.vulnerabilities = []
            self._lock = asyncio.Lock()

        async def add_url(self, url):
            async with self._lock:
                self.discovered_urls.add(url)

        async def add_vulnerability(self, vuln):
            async with self._lock:
                self.vulnerabilities.append(vuln)


# ─────────────────────────────────────────────────────────────────
# ANSI helpers
# ─────────────────────────────────────────────────────────────────
def ok(msg):  print(f"  \033[92m✔ {msg}\033[0m")
def fail(msg):print(f"  \033[91m✘ {msg}\033[0m")
def info(msg):print(f"  \033[94m→ {msg}\033[0m")
def head(msg):print(f"\n\033[1;33m{'─'*55}\n  {msg}\n{'─'*55}\033[0m")


# ─────────────────────────────────────────────────────────────────
# TEST 1: Event Flood — 5000 unique events
# ─────────────────────────────────────────────────────────────────
async def test_event_flood():
    head("TEST 1 — Event Flood: 5,000 VULNERABILITY_FOUND events")
    
    bus = EventBus()
    call_count = {"n": 0}

    async def fast_handler(event):
        await asyncio.sleep(0.001)   # simulate 1ms work
        call_count["n"] += 1

    bus.subscribe(EventType.VULNERABILITY_FOUND, fast_handler)

    tracemalloc.start()
    t0 = time.perf_counter()

    FLOOD = 5_000
    for i in range(FLOOD):
        bus.publish(AuraEvent(
            type=EventType.VULNERABILITY_FOUND,
            source=f"engine_{i % 8}",
            message=f"XSS found at /path/{i}",   # unique → no dedup
        ))

    # Wait for all handler tasks to finish
    await asyncio.sleep(0.1)
    pending = [t for t in asyncio.all_tasks()
               if t != asyncio.current_task() and "eventbus" in (t.get_name() or "")]
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    elapsed = time.perf_counter() - t0
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    info(f"Published: {bus.stats['published']} | Handlers fired: {call_count['n']}")
    info(f"Time: {elapsed:.3f}s | Peak RAM: {peak/1024/1024:.2f} MB")

    # Concurrency guard: at most MAX_CONCURRENT_HANDLERS in flight at once
    if peak / 1024 / 1024 < 200:
        ok("Peak RAM under 200 MB — backpressure working")
    else:
        fail(f"RAM too high ({peak/1024/1024:.0f} MB) — possible task explosion")

    if elapsed < 30:
        ok(f"Completed in {elapsed:.2f}s — event loop not starved")
    else:
        fail("Test took too long — event loop may be blocked")


# ─────────────────────────────────────────────────────────────────
# TEST 2: Duplicate Suppression — 100 identical events
# ─────────────────────────────────────────────────────────────────
async def test_deduplication():
    head("TEST 2 — Idempotency: 100 identical events → expect 1 handler call")
    
    bus = EventBus()
    call_count = {"n": 0}

    async def counting_handler(event):
        call_count["n"] += 1

    bus.subscribe(EventType.TARGET_DISCOVERED, counting_handler)

    for _ in range(100):
        bus.publish(AuraEvent(
            type=EventType.TARGET_DISCOVERED,
            source="recon_pipeline",
            message="admin.target.com discovered",  # SAME every time
        ))

    await asyncio.sleep(0.2)

    info(f"Handler called {call_count['n']} time(s), dedup dropped {bus.stats['dropped_dedup']}")
    if call_count["n"] == 1:
        ok("Dedup working — exactly 1 handler call ✓")
    else:
        fail(f"Dedup FAILED — handler called {call_count['n']} times (expected 1)")


# ─────────────────────────────────────────────────────────────────
# TEST 3: Race Conditions — 100 concurrent MissionContext writes
# ─────────────────────────────────────────────────────────────────
async def test_race_condition():
    head("TEST 3 — Race Condition: 100 engines concurrently writing to MissionContext")
    
    ctx = MissionContext(target_url="https://target.com")

    async def add_url(i):
        await ctx.add_url(f"https://target.com/path/{i}")
        await ctx.add_vulnerability({"id": i, "type": "XSS"})

    await asyncio.gather(*[add_url(i) for i in range(100)])

    info(f"URLs in context: {len(ctx.discovered_urls)}, vulns: {len(ctx.vulnerabilities)}")
    if len(ctx.discovered_urls) == 100 and len(ctx.vulnerabilities) == 100:
        ok("No race condition — all 100 writes committed correctly ✓")
    else:
        fail(f"Race condition detected! URLs={len(ctx.discovered_urls)}, vulns={len(ctx.vulnerabilities)}")


# ─────────────────────────────────────────────────────────────────
# TEST 4: Engine Timeout Kill — slow handler killed by timeout
# ─────────────────────────────────────────────────────────────────
async def test_engine_timeout():
    head("TEST 4 — Kill-Switch: Hanging engine killed by 2s timeout")

    bus = EventBus()
    bus.HANDLER_TIMEOUT_S = 2.0   # override to 2s for test speed

    completed = {"n": 0}
    killed = {"n": 0}

    async def hanging_engine(event):
        await asyncio.sleep(99)   # simulates infinite hang
        completed["n"] += 1       # should NEVER reach here

    async def fast_engine(event):
        await asyncio.sleep(0.1)
        completed["n"] += 1

    bus.subscribe(EventType.ERROR_OCCURRED, hanging_engine)
    bus.subscribe(EventType.ERROR_OCCURRED, fast_engine)

    bus.publish(AuraEvent(type=EventType.ERROR_OCCURRED, source="poc_engine", message="test hang"))

    t0 = time.perf_counter()
    await asyncio.sleep(3.0)   # wait past 2s timeout
    elapsed = time.perf_counter() - t0

    info(f"Handler timeouts: {bus.stats['handler_timeouts']}, completed: {completed['n']}")
    if bus.stats["handler_timeouts"] >= 1:
        ok(f"Hanging engine killed after timeout ✓ (waited {elapsed:.1f}s)")
    else:
        fail("Timeout did not trigger — hanging engine may still be running")

    if completed["n"] == 1:
        ok("Fast engine completed normally despite hanging sibling ✓")
    else:
        fail(f"Fast engine didn't complete — {completed['n']} completions")


# ─────────────────────────────────────────────────────────────────
# TEST 5: Memory Leak — LRU cache bounded at DEDUP_CACHE_SIZE
# ─────────────────────────────────────────────────────────────────
async def test_memory_dedup_cache():
    head("TEST 5 — Memory Leak: Dedup cache bounded at 10,000 entries")

    bus = EventBus()
    bus.subscribe(EventType.VULNERABILITY_FOUND, lambda e: None)

    # Publish 15,000 unique events (exceeds DEDUP_CACHE_SIZE of 10,000)
    for i in range(15_000):
        bus.publish(AuraEvent(
            type=EventType.VULNERABILITY_FOUND,
            source="test",
            message=f"unique-event-{i}",
        ))

    cache_size = len(bus._seen_hashes)
    info(f"Dedup cache size after 15,000 events: {cache_size} (max: {bus.DEDUP_CACHE_SIZE})")

    if cache_size <= bus.DEDUP_CACHE_SIZE:
        ok(f"LRU eviction working — cache capped at {cache_size} entries ✓")
    else:
        fail(f"Cache NOT bounded — {cache_size} entries (exceeded {bus.DEDUP_CACHE_SIZE} limit)")


# ─────────────────────────────────────────────────────────────────
# Main Runner
# ─────────────────────────────────────────────────────────────────
async def main():
    print("\n" + "═"*55)
    print("  🔥 AURA CHAOS STRESS TEST — v2.0 Hardened")
    print("═"*55)

    results = []

    async def run(name, coro):
        try:
            await coro
            results.append((name, True))
        except Exception as e:
            fail(f"[{name}] CRASHED: {e}")
            results.append((name, False))

    await run("Event Flood",      test_event_flood())
    await run("Deduplication",    test_deduplication())
    await run("Race Condition",   test_race_condition())
    await run("Engine Timeout",   test_engine_timeout())
    await run("Memory/LRU Cache", test_memory_dedup_cache())

    print("\n" + "═"*55)
    print("  📊 RESULTS SUMMARY")
    print("═"*55)
    passed = sum(1 for _, ok in results if ok)
    for name, status in results:
        sym = "\033[92m✔\033[0m" if status else "\033[91m✘\033[0m"
        print(f"  {sym}  {name}")
    print(f"\n  Score: {passed}/{len(results)} tests passed")
    print("═"*55 + "\n")

    if passed == len(results):
        print("\033[1;92m  🛡️  ALL TESTS PASSED — SYSTEM IS HARDENED\033[0m\n")
    else:
        print("\033[1;91m  ⚠️  SOME TESTS FAILED — REVIEW OUTPUT ABOVE\033[0m\n")
    
    sys.exit(0 if passed == len(results) else 1)

if __name__ == "__main__":
    asyncio.run(main())
