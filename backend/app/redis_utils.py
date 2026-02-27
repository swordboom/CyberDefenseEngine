import json
import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any

try:
    import redis
except Exception:  # pragma: no cover
    redis = None

logger = logging.getLogger(__name__)


def build_redis_client(redis_url: str, enabled: bool = True):
    if not enabled or redis is None:
        return None
    try:
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
        return client
    except Exception as exc:
        logger.warning("Redis unavailable, using local fallback: %s", exc)
        return None


class RateLimiter:
    def __init__(self, *, limit_per_minute: int, redis_client=None):
        self.limit = limit_per_minute
        self.redis = redis_client
        self.window_seconds = 60.0
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.redis is not None:
            minute_slot = int(time.time() // 60)
            redis_key = f"cybersaarthi:rl:{key}:{minute_slot}"
            count = self.redis.incr(redis_key)
            if count == 1:
                self.redis.expire(redis_key, 65)
            return count <= self.limit

        now = time.monotonic()
        with self._lock:
            queue = self._events[key]
            cutoff = now - self.window_seconds
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(now)
            return True


class CacheStore:
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._memory: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get_json(self, key: str) -> dict[str, Any] | None:
        if self.redis is not None:
            raw = self.redis.get(key)
            if not raw:
                return None
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None

        with self._lock:
            value = self._memory.get(key)
            if value is None:
                return None
            expires_at, raw = value
            if expires_at <= time.time():
                self._memory.pop(key, None)
                return None
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        payload = json.dumps(value)
        if self.redis is not None:
            self.redis.setex(key, ttl_seconds, payload)
            return
        with self._lock:
            self._memory[key] = (time.time() + ttl_seconds, payload)
