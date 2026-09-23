"""Session token revocation blocklist with Redis and in-memory TTL caching."""

import hashlib
import time

from gateway.storage.challenge_store import challenge_store


class TokenRevocationStore:
    """Manages revoked session token identifiers until expiration."""

    def __init__(self):
        self._memory_blocklist: dict[str, float] = {}

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def revoke(self, token: str, ttl_seconds: int = 3600) -> None:
        """Add session token hash to revocation blocklist."""
        token_hash = self._hash_token(token)
        # Prune expired entries
        now = time.time()
        self._memory_blocklist = {k: exp for k, exp in self._memory_blocklist.items() if exp > now}
        self._memory_blocklist[token_hash] = now + ttl_seconds

        # Store in Redis if available
        if challenge_store._redis_available and challenge_store._redis_client:
            try:
                await challenge_store._redis_client.setex(f"webauthn:revoked:{token_hash}", ttl_seconds, "1")
            except Exception:
                pass

    async def is_revoked(self, token: str) -> bool:
        """Check if session token is on revocation blocklist."""
        token_hash = self._hash_token(token)
        if challenge_store._redis_available and challenge_store._redis_client:
            try:
                val = await challenge_store._redis_client.get(f"webauthn:revoked:{token_hash}")
                if val:
                    return True
            except Exception:
                pass

        exp = self._memory_blocklist.get(token_hash)
        if exp and exp > time.time():
            return True
        return False


# Global singleton
token_revocation = TokenRevocationStore()
