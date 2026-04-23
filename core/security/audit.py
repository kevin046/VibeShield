"""
Tamper-Evident Audit Log — Cryptographic hash chaining.

Every audit entry is chained to the previous one using SHA-256.
If any entry is modified, added, or removed, the chain breaks.
This makes the audit log tamper-evident without requiring a
separate signing infrastructure.

Chain structure:
  entry[0].prev_hash = "GENESIS"
  entry[1].prev_hash = SHA256(entry[0])
  entry[n].hash = SHA256(entry[n].prev_hash + entry[n].data)

Verification: recompute chain from genesis, any mismatch = tampered.
"""

import json
import hashlib
import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from enum import Enum

logger = logging.getLogger("vibeshield.security.audit")


class AuditSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditCategory(Enum):
    CONTAINER_LIFECYCLE = "container_lifecycle"
    NETWORK_EGRESS = "network_egress"
    AGENT_COMMAND = "agent_command"
    SECURITY_VIOLATION = "security_violation"
    ESCROW_EVENT = "escrow_event"
    ACCESS_CONTROL = "access_control"
    INTEGRITY_CHECK = "integrity_check"


@dataclass
class AuditEntry:
    """A single tamper-evident audit log entry."""
    timestamp: float
    category: str
    severity: str
    event: str
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    details: dict = field(default_factory=dict)
    # Chain fields (computed, not user-set)
    prev_hash: str = ""
    entry_hash: str = ""
    sequence: int = 0

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry's content + previous hash."""
        content = json.dumps({
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "event": self.event,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode()).hexdigest()

    def seal(self):
        """Compute and set the entry hash."""
        self.entry_hash = self.compute_hash()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLog:
    """
    Tamper-evident append-only audit log.

    Every entry is cryptographically chained. The log can be exported
    as JSON and verified independently — no external signing required.

    Usage:
        log = AuditLog()
        log.record("container_lifecycle", "info", "sandbox_started", agent_id="a1")
        log.record("network_egress", "warning", "blocked_connection", details={"host": "evil.com"})
        assert log.verify_chain()  # True if untampered
        log.export("/var/log/vibeshield/audit.jsonl")
    """

    GENESIS_HASH = "GENESIS" * 4  # 28 chars, clearly non-SHA256

    def __init__(self, log_id: Optional[str] = None):
        self.log_id = log_id or hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
        self._entries: list[AuditEntry] = []
        self._index: dict[int, int] = {}  # sequence -> position in _entries

    @property
    def length(self) -> int:
        return len(self._entries)

    @property
    def last_hash(self) -> str:
        if not self._entries:
            return self.GENESIS_HASH
        return self._entries[-1].entry_hash

    def record(
        self,
        category: str | AuditCategory,
        severity: str | AuditSeverity,
        event: str,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditEntry:
        """
        Append a new entry to the audit chain.

        The entry is automatically chained to the previous one.
        """
        if isinstance(category, AuditCategory):
            category = category.value
        if isinstance(severity, AuditSeverity):
            severity = severity.value

        sequence = len(self._entries) + 1

        entry = AuditEntry(
            timestamp=time.time(),
            category=category,
            severity=severity,
            event=event,
            agent_id=agent_id,
            task_id=task_id,
            details=details or {},
            prev_hash=self.last_hash,
            sequence=sequence,
        )
        entry.seal()

        self._entries.append(entry)
        self._index[sequence] = len(self._entries) - 1

        logger.debug(f"[AUDIT #{sequence}] {category}: {event}")
        return entry

    def verify_chain(self) -> dict[str, Any]:
        """
        Verify the integrity of the entire chain.

        Returns:
            {"valid": bool, "broken_at": int|None, "reason": str}
        """
        prev_hash = self.GENESIS_HASH

        for i, entry in enumerate(self._entries):
            # Check sequence numbering
            if entry.sequence != i + 1:
                return {
                    "valid": False,
                    "broken_at": entry.sequence,
                    "reason": f"Sequence gap: expected {i + 1}, got {entry.sequence}",
                }

            # Check chain linkage
            if entry.prev_hash != prev_hash:
                return {
                    "valid": False,
                    "broken_at": entry.sequence,
                    "reason": f"Chain broken at entry {entry.sequence}: "
                              f"prev_hash mismatch (expected {prev_hash[:16]}..., "
                              f"got {entry.prev_hash[:16]}...)",
                }

            # Verify hash integrity
            expected_hash = entry.compute_hash()
            if entry.entry_hash != expected_hash:
                return {
                    "valid": False,
                    "broken_at": entry.sequence,
                    "reason": f"Hash mismatch at entry {entry.sequence}: "
                              f"entry was modified after sealing",
                }

            prev_hash = entry.entry_hash

        return {"valid": True, "broken_at": None, "reason": "Chain integrity verified"}

    def query(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query the audit log with filters."""
        results = []
        for entry in reversed(self._entries):
            if len(results) >= limit:
                break
            if category and entry.category != category:
                continue
            if severity and entry.severity != severity:
                continue
            if agent_id and entry.agent_id != agent_id:
                continue
            if since and entry.timestamp < since:
                continue
            if until and entry.timestamp > until:
                continue
            results.append(entry.to_dict())
        return results

    def export_jsonl(self, path: str):
        """Export the full log as JSON Lines (append-friendly format)."""
        with open(path, "a") as f:
            for entry in self._entries:
                f.write(entry.to_json() + "\n")
        logger.info(f"Audit log exported: {path} ({len(self._entries)} entries)")

    def import_jsonl(self, path: str) -> bool:
        """Import and verify a JSONL audit log. Returns True if chain is valid."""
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    entry = AuditEntry(**data)
                    self._entries.append(entry)
                    self._index[entry.sequence] = len(self._entries) - 1
            result = self.verify_chain()
            if not result["valid"]:
                logger.error(f"Imported log is tampered: {result['reason']}")
                self._entries.clear()
                self._index.clear()
                return False
            logger.info(f"Audit log imported: {len(self._entries)} entries, chain valid")
            return True
        except Exception as e:
            logger.error(f"Failed to import audit log: {e}")
            return False

    def statistics(self) -> dict:
        """Get statistics about the audit log."""
        if not self._entries:
            return {"total": 0}

        categories = {}
        severities = {}
        for entry in self._entries:
            categories[entry.category] = categories.get(entry.category, 0) + 1
            severities[entry.severity] = severities.get(entry.severity, 0) + 1

        return {
            "total": len(self._entries),
            "categories": categories,
            "severities": severities,
            "time_range": {
                "first": self._entries[0].timestamp,
                "last": self._entries[-1].timestamp,
            },
        }
