"""Transient challenge storage with strict TTL expiration and atomic consumption."""

import asyncio
import json
import logging
import time
from typing import Any

from gateway.config import settings

logger = logging.getLogger("gateway.challenge_store")


class ChallengeStore:
    """Manages transient WebAuthn challenges with strict TTL expiration.

    Supports Redis with transparent fallback to an in-memory TTL store.
    Challenges are strictly single-use (consumed atomically on verification).
    """

    def __init__(self):
        self._memory_store: dict[str, dict[str, Any]] = {}
        self._redis_client = None
        self._redis_available = False
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Attempt to connect to Redis; fall back to in-memory store if unavailable."""
        if settings.REDIS_URL:
            try:
                import redis.asyncio as aioredis
                client = aioredis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=1.0,
                )
                # Quick ping check
                await asyncio.wait_for(client.ping(), timeout=1.0)
                self._redis_client = client
                self._redis_available = True
                logger.info("Connected to Redis for WebAuthn challenge caching.")
                return
            except Exception as ex:
                logger.info(
                    f"Redis unavailable ({ex}). Operating in zero-cost in-memory challenge store mode."
                )
        self._redis_available = False

    async def save_challenge(
        self,
        challenge_key: str,
        challenge: str,
        user_id: str | None = None,
        extra_data: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        """Save a challenge nonce with a strict TTL (time-to-live)."""
        ttl = ttl_seconds or settings.CHALLENGE_TIMEOUT_SECONDS
        payload = {
            "challenge": challenge,
            "user_id": user_id,
            "created_at": time.time(),
            "expires_at": time.time() + ttl,
            "extra": extra_data or {},
        }

        if self._redis_available and self._redis_client:
            try:
                redis_key = f"webauthn:challenge:{challenge_key}"
                await self._redis_client.setex(
                    redis_key,
                    ttl,
                    json.dumps(payload),
                )
                return
            except Exception as ex:
                logger.warning(f"Redis set failed, falling back to memory: {ex}")

        # In-memory storage with lock
        async with self._lock:
            # Clean expired items periodically
            now = time.time()
            expired_keys = [k for k, v in self._memory_store.items() if v.get("expires_at", 0) < now]
            for k in expired_keys:
                self._memory_store.pop(k, None)

            self._memory_store[challenge_key] = payload

    async def consume_challenge(self, challenge_key: str) -> dict[str, Any] | None:
        """Atomically fetch and delete the challenge to prevent replay attacks."""
        if self._redis_available and self._redis_client:
            try:
                redis_key = f"webauthn:challenge:{challenge_key}"
                # Atomically get and delete in Redis
                pipeline = self._redis_client.pipeline()
                pipeline.get(redis_key)
                pipeline.delete(redis_key)
                results = await pipeline.execute()
                data_str = results[0]
                if data_str:
                    return json.loads(data_str)
                return None
            except Exception as ex:
                logger.warning(f"Redis consume failed, checking in-memory: {ex}")

        # In-memory retrieval with atomic pop
        async with self._lock:
            entry = self._memory_store.pop(challenge_key, None)
            if not entry:
                return None
            if entry.get("expires_at", 0) < time.time():
                return None
            return entry

    async def get_challenge(self, challenge_key: str) -> dict[str, Any] | None:
        """Read challenge without consuming (used for inspection / debugging)."""
        if self._redis_available and self._redis_client:
            try:
                redis_key = f"webauthn:challenge:{challenge_key}"
                data_str = await self._redis_client.get(redis_key)
                if data_str:
                    return json.loads(data_str)
                return None
            except Exception:
                pass

        async with self._lock:
            entry = self._memory_store.get(challenge_key)
            if not entry or entry.get("expires_at", 0) < time.time():
                return None
            return entry


# Global singleton instance
challenge_store = ChallengeStore()
