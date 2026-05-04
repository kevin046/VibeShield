"""
Rate Limiter Middleware — Token bucket rate limiter for ClawMolt integration.

Provides per-agent, per-IP, and global rate limiting using a token bucket
algorithm. Designed for integration with FastAPI/Starlette but can be
used with any async Python framework.

Features:
- Per-agent rate limiting (by agent_id)
- Per-IP rate limiting (by client IP)
- Global capacity limiting (total requests across all agents)
- Token bucket with burst support
- Sliding window for sustained rate tracking
- Simple in-memory store (Redis optional for distributed deployments)
"""

import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger("vibeshield.security.ratelimit")


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a single scope."""
    requests_per_second: float = 10.0     # Sustained rate
    burst_size: int = 20                   # Maximum burst
    cooldown_seconds: float = 60.0         # How long to track before reset


class TokenBucket:
    """
    Token bucket rate limiter.

    Tokens are added at `requests_per_second` rate.
    Each request consumes one token.
    Bursts of up to `burst_size` tokens are allowed.
    """

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = float(config.burst_size)
        self.last_refill = time.monotonic()
        self.max_tokens = float(config.burst_size)
        self.rate = config.requests_per_second

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill

        # Refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def fill_ratio(self) -> float:
        """How full the bucket is (0.0 = empty, 1.0 = full)."""
        return self.tokens / self.max_tokens


class SlidingWindowCounter:
    """
    Sliding window rate counter for tracking sustained rates.

    Tracks request timestamps within a time window to enforce
    sustained rate limits beyond simple token bucket bursts.
    """

    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def allow(self) -> tuple[bool, int]:
        """
        Check if request is allowed within the sliding window.

        Returns:
            (allowed: bool, current_count: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old timestamps
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.pop(0)

        current_count = len(self._timestamps)
        if current_count >= self.max_requests:
            return False, current_count

        self._timestamps.append(now)
        return True, current_count + 1


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    retry_after: float = 0.0  # seconds to wait before retrying
    remaining: int = 0
    limit: int = 0
    scope: str = ""


class RateLimiter:
    """
    Multi-scope rate limiter with token bucket + sliding window.

    Supports:
    - Per-agent limits
    - Per-IP limits
    - Global capacity limits
    - Custom scope limits

    Usage (FastAPI middleware example):
        limiter = RateLimiter()
        app.add_middleware(RateLimitMiddleware, limiter=limiter)
    """

    def __init__(
        self,
        default_config: Optional[RateLimitConfig] = None,
        agent_config: Optional[RateLimitConfig] = None,
        ip_config: Optional[RateLimitConfig] = None,
        global_config: Optional[RateLimitConfig] = None,
        on_ratelimit: Optional[Callable[[str, str, float], None]] = None,
    ):
        self.default_config = default_config or RateLimitConfig(
            requests_per_second=10.0,
            burst_size=20,
        )
        self.agent_config = agent_config or RateLimitConfig(
            requests_per_second=5.0,
            burst_size=10,
            cooldown_seconds=120.0,
        )
        self.ip_config = ip_config or RateLimitConfig(
            requests_per_second=20.0,
            burst_size=40,
        )
        self.global_config = global_config or RateLimitConfig(
            requests_per_second=50.0,
            burst_size=100,
        )
        self.on_ratelimit = on_ratelimit  # alert callback

        # Token buckets keyed by scope identifier
        self._buckets: dict[str, TokenBucket] = {}
        self._windows: dict[str, SlidingWindowCounter] = {}

    def _bucket_key(self, scope: str, identifier: str) -> str:
        """Generate a bucket key from scope and identifier."""
        raw = f"{scope}:{identifier}"
        # Hash to prevent memory from unbounded identifier strings
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _get_bucket(self, key: str, config: RateLimitConfig) -> TokenBucket:
        """Get or create a token bucket."""
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(config)
            # Cleanup stale buckets if we're tracking too many
            if len(self._buckets) > 10000:
                self._cleanup_stale_buckets()
        return self._buckets[key]

    def check_agent(self, agent_id: str) -> RateLimitResult:
        """Check rate limit for a specific agent."""
        return self._check("agent", agent_id, self.agent_config)

    def check_ip(self, ip_address: str) -> RateLimitResult:
        """Check rate limit for a specific IP."""
        return self._check("ip", ip_address, self.ip_config)

    def check_global(self) -> RateLimitResult:
        """Check global rate limit."""
        return self._check("global", "_", self.global_config)

    def check_all(self, agent_id: Optional[str] = None,
                  ip_address: Optional[str] = None) -> RateLimitResult:
        """Check all applicable rate limits. Returns the most restrictive result."""
        results = []
        if agent_id:
            results.append(self.check_agent(agent_id))
        if ip_address:
            results.append(self.check_ip(ip_address))
        results.append(self.check_global())

        # Return the most restrictive result
        blocked = [r for r in results if not r.allowed]
        if blocked:
            return blocked[0]

        # Return the one with lowest remaining
        return min(results, key=lambda r: r.remaining)

    def reset(self, scope: str, identifier: str):
        """Reset rate limit for a specific scope and identifier."""
        key = self._bucket_key(scope, identifier)
        self._buckets.pop(key, None)
        self._windows.pop(key, None)

    def stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "total_buckets": len(self._buckets),
            "active_buckets": sum(
                1 for b in self._buckets.values()
                if b.fill_ratio < 0.9
            ),
            "config": {
                "global": f"{self.global_config.requests_per_second}/s",
                "agent": f"{self.agent_config.requests_per_second}/s",
                "ip": f"{self.ip_config.requests_per_second}/s",
                "burst": self.agent_config.burst_size,
            },
        }

    def _check(self, scope: str, identifier: str,
               config: RateLimitConfig) -> RateLimitResult:
        """Internal rate limit check."""
        key = self._bucket_key(scope, identifier)
        bucket = self._get_bucket(key, config)

        if not bucket.consume():
            # Rate limited
            retry_after = (1.0 - bucket.tokens) / bucket.rate if bucket.rate > 0 else config.cooldown_seconds
            retry_after = max(retry_after, 0.1)

            if self.on_ratelimit:
                try:
                    self.on_ratelimit(scope, identifier, retry_after)
                except Exception as e:
                    logger.error(f"Rate limit callback failed: {e}")

            return RateLimitResult(
                allowed=False,
                retry_after=round(retry_after, 2),
                remaining=0,
                limit=int(config.burst_size),
                scope=scope,
            )

        return RateLimitResult(
            allowed=True,
            retry_after=0.0,
            remaining=max(0, int(bucket.tokens)),
            limit=int(config.burst_size),
            scope=scope,
        )

    def _cleanup_stale_buckets(self):
        """Remove buckets that haven't been used recently."""
        now = time.monotonic()
        stale_keys = [
            k for k, b in self._buckets.items()
            if now - b.last_refill > 300  # 5 minutes stale
        ]
        for k in stale_keys:
            del self._buckets[k]
        if stale_keys:
            logger.info(f"Rate limiter: cleaned up {len(stale_keys)} stale buckets")
