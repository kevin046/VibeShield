"""VibeShield Security Framework — Configuration"""

import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class SandboxConfig:
    """Layer 1 configuration for container isolation."""
    sandbox_image: str = os.getenv("VIBESHIELD_SANDBOX_IMAGE", "vibeshield/base:latest")
    network_mode: str = os.getenv("VIBESHIELD_NETWORK_MODE", "none")  # none = total isolation
    memory_limit: str = os.getenv("VIBESHIELD_MEMORY_LIMIT", "512m")
    cpu_quota: int = int(os.getenv("VIBESHIELD_CPU_QUOTA", "50000"))  # microseconds per period
    cpu_period: int = int(os.getenv("VIBESHIELD_CPU_PERIOD", "100000"))
    tmpfs_size: str = os.getenv("VIBESHIELD_TMPFS_SIZE", "100M")
    timeout_seconds: int = int(os.getenv("VIBESHIELD_TASK_TIMEOUT", "300"))
    cap_drop_all: bool = True
    no_new_privileges: bool = True


@dataclass
class OrchestratorConfig:
    """Layer 2 configuration for agent verification."""
    ping_timeout_ms: int = int(os.getenv("VIBESHIELD_PING_TIMEOUT", "5000"))
    echo_timeout_ms: int = int(os.getenv("VIBESHIELD_ECHO_TIMEOUT", "10000"))
    max_workers: int = int(os.getenv("VIBESHIELD_MAX_AGENTS", "50"))
    challenge_difficulty: str = os.getenv("VIBESHIELD_DIFFICULTY", "hard")
    latency_threshold_fast: float = float(os.getenv("VIBESHIELD_LATENCY_FAST", "1.8"))
    latency_threshold_slow: float = float(os.getenv("VIBESHIELD_LATENCY_SLOW", "5.0"))


@dataclass
class EscrowConfig:
    """Layer 3 configuration for bounty settlement."""
    settlement_timeout: int = int(os.getenv("VIBESHIELD_SETTLEMENT_TIMEOUT", "3600"))
    consensus_agents: int = int(os.getenv("VIBESHIELD_CONSENSUS_AGENTS", "3"))
    dispute_threshold: float = float(os.getenv("VIBESHIELD_DISPUTE_THRESHOLD", "0.7"))
    reputation_decay_factor: float = float(os.getenv("VIBESHIELD_RS_DECAY", "0.95"))
    verified_multiplier: float = float(os.getenv("VIBESHIELD_VERIFIED_MULTIPLIER", "1.05"))
    min_reputation: float = float(os.getenv("VIBESHIELD_RS_MIN", "0.3"))


@dataclass
class VibeShieldConfig:
    """Top-level framework configuration."""
    mode: str = os.getenv("VIBESHIELD_MODE", "production")  # production, development, testing
    log_level: str = os.getenv("VIBESHIELD_LOG_LEVEL", "INFO")
    data_dir: Path = Path(os.getenv("VIBESHIELD_DATA_DIR", "/var/lib/vibeshield"))

    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    escrow: EscrowConfig = field(default_factory=EscrowConfig)

    @property
    def is_production(self) -> bool:
        return self.mode == "production"
