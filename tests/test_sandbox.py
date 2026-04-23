"""Tests for Layer 1: Confidential Sandbox."""

import subprocess as subprocess_module
from unittest.mock import patch, MagicMock
from core.layer1_sandbox import (
    KrakenSandbox, SandboxState, SandboxResult, EgressRule, SandboxConfig
)


class TestSandboxConfig:
    def test_default_config_is_secure(self):
        config = SandboxConfig()
        assert config.network_mode == "none"
        assert config.cap_drop_all is True
        assert config.no_new_privileges is True

    def test_config_from_env(self, monkeypatch):
        # Set env vars BEFORE creating the config object
        monkeypatch.setenv("KRAKEN_NETWORK_MODE", "restricted")
        monkeypatch.setenv("KRAKEN_MEMORY_LIMIT", "1g")
        monkeypatch.setenv("KRAKEN_TASK_TIMEOUT", "600")
        # Reimport to get fresh module-level defaults
        import importlib
        import core.config
        importlib.reload(core.config)
        from core.config import SandboxConfig as SC
        config = SC()
        assert config.network_mode == "restricted"
        assert config.memory_limit == "1g"
        assert config.timeout_seconds == 600


class TestEgressRule:
    def test_basic_rule(self):
        rule = EgressRule(protocol="tcp", host="api.example.com", port=443)
        assert rule.protocol == "tcp"
        assert rule.port == 443


class TestKrakenSandbox:
    def test_init_creates_unique_name(self):
        s1 = KrakenSandbox("task-1")
        s2 = KrakenSandbox("task-2")
        assert s1.container_name != s2.container_name
        assert s1.state == SandboxState.PENDING
        assert s1.task_id == "task-1"

    def test_deploy_agent_network_none(self):
        config = SandboxConfig(network_mode="none")
        sandbox = KrakenSandbox("test-task", config=config)

        with patch("core.layer1_sandbox.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = sandbox.deploy_agent("encrypted_payload")

            assert result.state in (SandboxState.COMPLETED, SandboxState.FAILED)
            assert result.task_id == "test-task"

            # The first call should be podman run with --network=none
            call_args = mock_run.call_args_list[0][0][0]
            assert "--network" in call_args
            idx = call_args.index("--network")
            assert call_args[idx + 1] == "none"

    def test_deploy_agent_caps_dropped(self):
        sandbox = KrakenSandbox("test-task")

        with patch("core.layer1_sandbox.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            sandbox.deploy_agent("encrypted_payload")

            call_args = mock_run.call_args_list[0][0][0]
            assert "--cap-drop" in call_args
            idx = call_args.index("--cap-drop")
            assert call_args[idx + 1] == "ALL"

    def test_deploy_agent_timeout(self):
        config = SandboxConfig(timeout_seconds=1)
        sandbox = KrakenSandbox("test-task", config=config)

        with patch("core.layer1_sandbox.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess_module.TimeoutExpired(cmd="podman", timeout=1)
            with patch.object(sandbox, "cryptographic_shred"):
                result = sandbox.deploy_agent("payload")

        assert result.state == SandboxState.TIMEOUT

    def test_cryptographic_shred(self):
        sandbox = KrakenSandbox("test-task")
        sandbox.state = SandboxState.RUNNING

        with patch("core.layer1_sandbox.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            sandbox.cryptographic_shred()

        assert sandbox.state == SandboxState.SHREDDED
        # Should call podman stop, rm, and volume rm
        assert mock_run.call_count >= 2
