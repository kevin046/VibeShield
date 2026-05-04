"""Tests for Layer 2: Orchestration Engine (Heartbeat)."""

import pytest
from core.layer2_orchestrator import (
    OrchestrationEngine, HeartbeatStatus, HeartbeatResult,
    OrchestratorConfig
)


class TestHeartbeatConfig:
    def test_default_config(self):
        engine = OrchestrationEngine()
        assert engine.config.api_url == "https://api.clawmolt.ai"
        assert engine.config.heartbeat_interval == 600
        assert engine.config.offline_threshold == 1800
        assert engine.config.max_workers == 50

    def test_custom_config(self):
        config = OrchestratorConfig(
            api_url="https://staging.clawmolt.ai",
            heartbeat_interval=300,
            offline_threshold=900,
        )
        engine = OrchestrationEngine(config=config)
        assert engine.config.api_url == "https://staging.clawmolt.ai"
        assert engine.config.heartbeat_interval == 300
        assert engine.config.offline_threshold == 900


class TestHeartbeatResult:
    def test_passed_live(self):
        result = HeartbeatResult(
            agent_id="test-agent",
            status=HeartbeatStatus.LIVE,
            api_key="test-key",
            api_url="https://api.clawmolt.ai/api/v1/agents/test/heartbeat",
            http_status=200,
            message="OK",
        )
        assert result.passed is True

    def test_not_passed(self):
        for status in (HeartbeatStatus.STALE, HeartbeatStatus.OFFLINE, HeartbeatStatus.ERROR):
            result = HeartbeatResult(
                agent_id="test-agent",
                status=status,
                api_key="test-key",
                api_url="https://api.clawmolt.ai/api/v1/agents/test/heartbeat",
            )
            assert result.passed is False


class TestHealthCheck:
    def test_no_heartbeat_is_offline(self):
        engine = OrchestrationEngine()
        status = engine.check_agent_health("unknown-agent")
        assert status == HeartbeatStatus.OFFLINE

    def test_agent_heartbeat_status(self, monkeypatch):
        engine = OrchestrationEngine()
        # Simulate a recent heartbeat by directly setting _last_heartbeat
        import time
        engine._last_heartbeat["test-agent"] = time.time()
        status = engine.check_agent_health("test-agent")
        assert status == HeartbeatStatus.LIVE

    def test_agent_stale_heartbeat(self, monkeypatch):
        engine = OrchestrationEngine()
        import time
        # Set last heartbeat far in the past (beyond 2x interval but within threshold)
        engine._last_heartbeat["test-agent"] = time.time() - 900  # 15 min ago
        status = engine.check_agent_health("test-agent")
        assert status == HeartbeatStatus.LIVE  # Still within 2x (1200s) interval

    def test_agent_stale_beyond_double(self, monkeypatch):
        engine = OrchestrationEngine()
        import time
        # 2x interval + 1 = 1201 seconds ago → STALE (within offline_threshold)
        engine._last_heartbeat["test-agent"] = time.time() - 1201
        status = engine.check_agent_health("test-agent")
        assert status == HeartbeatStatus.STALE

    def test_agent_offline(self, monkeypatch):
        engine = OrchestrationEngine()
        import time
        # Beyond offline threshold
        engine._last_heartbeat["test-agent"] = time.time() - 2000
        status = engine.check_agent_health("test-agent")
        assert status == HeartbeatStatus.OFFLINE


class TestUptime:
    def test_no_heartbeat_returns_none(self):
        engine = OrchestrationEngine()
        uptime = engine.get_uptime("unknown")
        assert uptime is None

    def test_uptime_returns_seconds(self, monkeypatch):
        engine = OrchestrationEngine()
        import time
        engine._last_heartbeat["test-agent"] = time.time() - 60
        uptime = engine.get_uptime("test-agent")
        assert uptime is not None
        assert 59 <= uptime <= 61
