"""
aura.core.events — HARDENED v2.0

Implements a hardened Event Bus (Pub/Sub) with:
- Backpressure Management (bounded semaphore on concurrent handlers)
- Deduplication (LRU hash cache to prevent duplicate event chains)
- Per-handler timeout (prevents a slow subscriber from stalling the bus)
- Drop counter for observability
"""

from typing import Any, Callable, Dict, List
import asyncio
from collections import OrderedDict
from enum import Enum
from pydantic import BaseModel


class EventType(str, Enum):
    PHASE_START = "PHASE_START"
    PHASE_END = "PHASE_END"
    TARGET_DISCOVERED = "TARGET_DISCOVERED"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    ERROR_OCCURRED = "ERROR_OCCURRED"
    PROGRESS_UPDATE = "PROGRESS_UPDATE"
    SYSTEM_LOG = "SYSTEM_LOG"


class AuraEvent(BaseModel):
    type: EventType
    source: str
    message: str
    data: Dict[str, Any] = {}


class EventBus:
    """
    Hardened centralized async Event Bus for Pub/Sub architecture.

    Guarantees:
    - Max 50 concurrent handler coroutines (backpressure via Semaphore)
    - Duplicate events (same type+source+message) are silently dropped
    - Each async handler has a 10s timeout before it is force-killed
    - Dedup cache is bounded at 10,000 entries (LRU eviction)
    """

    MAX_CONCURRENT_HANDLERS = 50
    HANDLER_TIMEOUT_S = 10.0
    DEDUP_CACHE_SIZE = 10_000

    def __init__(self):
        self._subscribers: Dict[EventType, List[Callable]] = {
            t: [] for t in EventType
        }
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_HANDLERS)
        self._seen_hashes: OrderedDict = OrderedDict()
        self.stats = {"published": 0, "dropped_dedup": 0, "handler_timeouts": 0}

    def subscribe(self, event_type: EventType, callback: Callable[[AuraEvent], None]):
        """Register a callback for a specific event type."""
        self._subscribers[event_type].append(callback)

    def _is_duplicate(self, event: AuraEvent) -> bool:
        """LRU deduplication check. Returns True if this event was already seen."""
        event_hash = hash((event.type, event.source, event.message))
        if event_hash in self._seen_hashes:
            return True
        # Add to cache with LRU eviction
        self._seen_hashes[event_hash] = True
        if len(self._seen_hashes) > self.DEDUP_CACHE_SIZE:
            self._seen_hashes.popitem(last=False)  # Evict oldest entry
        return False

    def publish(self, event: AuraEvent):
        """
        Dispatch an event to all registered subscribers.
        - Deduplicates identical events
        - Caps concurrent async handlers via semaphore
        - Sync callbacks are called inline (they must be fast)
        """
        self.stats["published"] += 1

        if self._is_duplicate(event):
            self.stats["dropped_dedup"] += 1
            return

        for callback in self._subscribers[event.type]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.create_task(
                        self._guarded_call(callback, event),
                        name=f"eventbus-{event.type}-{callback.__name__}"
                    )
                else:
                    callback(event)
            except Exception as e:
                print(f"[EventBus] Error dispatching {event.type} to {callback}: {e}")

    async def _guarded_call(self, callback: Callable, event: AuraEvent):
        """
        Runs an async handler under:
        1. A semaphore (max concurrency cap)
        2. A timeout (prevents infinite hangs)
        """
        async with self._semaphore:
            try:
                await asyncio.wait_for(callback(event), timeout=self.HANDLER_TIMEOUT_S)
            except asyncio.TimeoutError:
                self.stats["handler_timeouts"] += 1
                print(f"[EventBus] ⚠️  Handler timed out for event {event.type} from {event.source}")
            except Exception as e:
                print(f"[EventBus] Handler error for {event.type}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Returns bus health metrics."""
        return {
            **self.stats,
            "dedup_cache_size": len(self._seen_hashes),
        }

    def reset_dedup_cache(self):
        """Clear deduplication cache between missions."""
        self._seen_hashes.clear()


# Global singleton instance
bus = EventBus()
