"""
Layer 2: Orchestration Engine — Agent Heartbeat Verification

Replaces the legacy "Ping & Echo" challenge protocol with ClawMolt's
HTTP heartbeat endpoint for reliable agent health checking:

1. HEARTBEAT: Agent sends POST /api/v1/agents/{agent_id}/heartbeat
   with its API key in the X-API-Key header
2. STATUS: ClawMolt returns the agent's current status (ONLINE/BUSY/etc.)
3. VERIFY: The response confirms the agent is alive and reachable

Heartbeat lifecycle:
- Agents heartbeat every 10 minutes (configurable)
- Offline threshold: 30 minutes without heartbeat
- Authentication: X-API-Key header or Bearer cm_ token
"""

import time
import logging
import json
import urllib.request
import urllib.error
import secrets
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from core.config import OrchestratorConfig

logger = logging.getLogger("vibeshield.layer2")


class HeartbeatStatus(Enum):
    LIVE = "LIVE"
    STALE = "STALE"
    OFFLINE = "OFFLINE"
    ERROR = "ERROR"


@dataclass
class HeartbeatResult:
    """Result of an agent heartbeat check."""
    agent_id: str
    status: HeartbeatStatus
    api_key: str
    api_url: str
    http_status: int = 0
    message: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def passed(self) -> bool:
        return self.status == HeartbeatStatus.LIVE


# ─── Nonce cache for replay protection ──────────────────────────────────
_NONCE_CACHE: dict[str, float] = {}
"""Cache of used nonces (nonce -> timestamp). Prevents replay attacks."""


def _generate_nonce() -> str:
    """Generate a cryptographically random nonce."""
    return secrets.token_hex(16)


def _cleanup_nonces(max_age: float = 300.0):
    """Remove expired nonces from cache."""
    cutoff = time.time() - max_age
    stale = [k for k, v in _NONCE_CACHE.items() if v < cutoff]
    for k in stale:
        del _NONCE_CACHE[k]
    return len(stale)


class OrchestrationEngine:
    """
    Verifies agent liveness via ClawMolt heartbeat API.

    Agents are expected to send periodic heartbeats to the ClawMolt
    platform. This engine manages heartbeat scheduling, tracks
    agent status, and detects offline agents.
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        # Track last successful heartbeat per agent
        self._last_heartbeat: dict[str, float] = {}

    def send_heartbeat(
        self,
        agent_id: str,
        api_key: str,
        status: str = "ONLINE",
        heat_current: Optional[int] = None,
        local_llm_model: Optional[str] = None,
    ) -> HeartbeatResult:
        """
        Send a heartbeat to ClawMolt for the given agent.

        POST /api/v1/agents/{agent_id}/heartbeat
        Headers: X-API-Key: <api_key>, Content-Type: application/json
        Body: { "status": "ONLINE", "heat_current": ..., "local_llm_model": "..." }

        Nonce-based replay protection is included in every heartbeat.
        Args:
            agent_id: UUID of the agent
            api_key: Agent's API key for authentication
            status: ONLINE | BUSY | COOLDOWN
            heat_current: Optional current heat value (0-100)
            local_llm_model: Optional model identifier

        Returns:
            HeartbeatResult with status from the server
        """
        url = f"{self.config.api_url.rstrip('/')}/api/v1/agents/{agent_id}/heartbeat"

        # Build request body
        nonce = _generate_nonce()
        body_dict: dict = {"status": status, "nonce": nonce}
        if heat_current is not None:
            body_dict["heat_current"] = heat_current
        if local_llm_model:
            body_dict["local_llm_model"] = local_llm_model
        body = json.dumps(body_dict).encode("utf-8")

        # Build request
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json",
                "User-Agent": "VibeShield/2.0",
                "X-Nonce": nonce,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                req, timeout=self.config.heartbeat_timeout
            ) as resp:
                response_body = resp.read().decode("utf-8")
                data = json.loads(response_body) if response_body else {}

                # Success — agent is alive
                server_status = data.get("status", "ONLINE")
                self._last_heartbeat[agent_id] = time.time()
                # Record nonce for replay protection
                _NONCE_CACHE[nonce] = time.time()
                _cleanup_nonces()

                # Map server status to HeartbeatStatus
                if server_status == "ONLINE":
                    status_enum = HeartbeatStatus.LIVE
                elif server_status in ("BUSY", "COOLDOWN"):
                    # Agent is still alive, just busy
                    status_enum = HeartbeatStatus.LIVE
                else:
                    status_enum = HeartbeatStatus.STALE

                return HeartbeatResult(
                    agent_id=agent_id,
                    status=status_enum,
                    api_key=api_key,
                    api_url=url,
                    http_status=resp.status,
                    message=f"Heartbeat acknowledged — server status: {server_status}",
                )

        except urllib.error.HTTPError as e:
            http_status = e.code
            try:
                error_body = e.read().decode("utf-8")
                error_data = json.loads(error_body)
                detail = error_data.get("detail", str(e))
            except (json.JSONDecodeError, AttributeError):
                detail = str(e)

            if http_status == 401:
                return HeartbeatResult(
                    agent_id=agent_id,
                    status=HeartbeatStatus.ERROR,
                    api_key=api_key,
                    api_url=url,
                    http_status=http_status,
                    message=f"Authentication failed — invalid API key: {detail}",
                )
            elif http_status == 404:
                return HeartbeatResult(
                    agent_id=agent_id,
                    status=HeartbeatStatus.OFFLINE,
                    api_key=api_key,
                    api_url=url,
                    http_status=http_status,
                    message=f"Agent not found on ClawMolt: {detail}",
                )
            else:
                return HeartbeatResult(
                    agent_id=agent_id,
                    status=HeartbeatStatus.ERROR,
                    api_key=api_key,
                    api_url=url,
                    http_status=http_status,
                    message=f"HTTP {http_status}: {detail}",
                )

        except urllib.error.URLError as e:
            return HeartbeatResult(
                agent_id=agent_id,
                status=HeartbeatStatus.ERROR,
                api_key=api_key,
                api_url=url,
                http_status=0,
                message=f"Connection failed — {e.reason}",
            )

        except OSError as e:
            return HeartbeatResult(
                agent_id=agent_id,
                status=HeartbeatStatus.ERROR,
                api_key=api_key,
                api_url=url,
                http_status=0,
                message=f"Network error: {e}",
            )

    def check_agent_health(self, agent_id: str) -> HeartbeatStatus:
        """
        Check if an agent is still alive based on last recorded heartbeat.

        Returns LIVE if heartbeat within interval + grace period.
        Returns STALE if last heartbeat was a while ago.
        Returns OFFLINE if no heartbeat recorded or beyond threshold.
        """
        last = self._last_heartbeat.get(agent_id)
        if last is None:
            return HeartbeatStatus.OFFLINE

        elapsed = time.time() - last
        if elapsed < self.config.heartbeat_interval * 2:
            # Within 2x heartbeat interval — still alive
            return HeartbeatStatus.LIVE
        elif elapsed < self.config.offline_threshold:
            return HeartbeatStatus.STALE
        else:
            return HeartbeatStatus.OFFLINE

    def get_uptime(self, agent_id: str) -> Optional[float]:
        """Get seconds since last successful heartbeat, or None if never heartbeated."""
        last = self._last_heartbeat.get(agent_id)
        if last is None:
            return None
        return time.time() - last

    def batch_heartbeat(
        self, agents: list[dict]
    ) -> list[HeartbeatResult]:
        """
        Send heartbeats for multiple agents.

        Each dict in agents must have:
            - agent_id: str
            - api_key: str
            - status: str (optional, default "ONLINE")

        Returns list of HeartbeatResult in same order.
        """
        results = []
        for agent in agents:
            result = self.send_heartbeat(
                agent_id=agent["agent_id"],
                api_key=agent["api_key"],
                status=agent.get("status", "ONLINE"),
                heat_current=agent.get("heat_current"),
                local_llm_model=agent.get("local_llm_model"),
            )
            results.append(result)
        return results


# CLI entrypoint
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VibeShield Layer 2 Heartbeat Engine")
    parser.add_argument("--agent-id", required=True, help="Agent UUID")
    parser.add_argument("--api-key", required=True, help="Agent API key")
    parser.add_argument("--status", default="ONLINE", choices=["ONLINE", "BUSY", "COOLDOWN"])
    parser.add_argument("--api-url", default="https://api.clawmolt.ai")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    config = OrchestratorConfig(api_url=args.api_url)
    engine = OrchestrationEngine(config)

    result = engine.send_heartbeat(
        agent_id=args.agent_id,
        api_key=args.api_key,
        status=args.status,
    )

    print(f"Agent:     {result.agent_id}")
    print(f"Status:    {result.status.value}")
    print(f"HTTP:      {result.http_status}")
    print(f"Message:   {result.message}")
    print(f"Passed:    {result.passed}")
