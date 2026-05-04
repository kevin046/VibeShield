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

Merkle Tree:
  A balanced binary Merkle tree is built over the chain for
  efficient selective verification. The Merkle root commits
  to the entire log — useful for periodic anchoring.

Verification:
  - verify_chain(): recompute chain from genesis
  - verify_merkle(): recompute Merkle root
  Any mismatch = tampered.
"""

import json
import hashlib
import time
import os
import math
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, Any, Callable
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
    Tamper-evident append-only audit log with Merkle tree verification.

    Every entry is cryptographically chained with SHA-256. A Merkle
    tree is built over the entire chain for efficient selective
    verification and anchoring.

    Supports:
    - Append-only recording with hash chaining
    - Full chain verification (detects any modification)
    - Merkle tree computation and root anchoring
    - Filtered queries with pagination
    - JSONL import/export
    - Periodic persistence
    - Alert callbacks for CRITICAL events
    """

    GENESIS_HASH = "GENESIS" * 4  # 28 chars, clearly non-SHA256

    def __init__(self, log_id: Optional[str] = None, audit_dir: str = "/var/lib/vibeshield/audit",
                 on_critical: Optional[Callable[[AuditEntry], None]] = None):
        self.log_id = log_id or hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
        self.audit_dir = audit_dir
        self._entries: list[AuditEntry] = []
        self._index: dict[int, int] = {}  # sequence -> position in _entries
        self._on_critical = on_critical  # alert callback for CRITICAL events
        self._dirty = False  # tracks if export is needed

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
        If severity is CRITICAL and on_callback is set, fires the alert.
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
        self._dirty = True

        logger.debug(f"[AUDIT #{sequence}] {severity.upper()} {category}: {event}")

        # Fire alert callback for CRITICAL events
        if severity == AuditSeverity.CRITICAL.value and self._on_critical:
            try:
                self._on_critical(entry)
            except Exception as e:
                logger.error(f"Audit alert callback failed: {e}")

        return entry

    # ─── Chain Verification ────────────────────────────────────────────────

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

    # ─── Merkle Tree ───────────────────────────────────────────────────────

    def compute_merkle_root(self) -> str:
        """
        Compute the Merkle tree root over the audit chain.

        Builds a balanced binary Merkle tree from the entry hashes.
        The root commits to the entire log — useful for periodic
        anchoring to a public ledger or timestamp authority.
        """
        if not self._entries:
            return hashlib.sha256(b"EMPTY_LOG").hexdigest()

        leaves = [entry.entry_hash for entry in self._entries]
        return self._merkle_root(leaves)

    def compute_merkle_proof(self, sequence: int) -> list[str]:
        """
        Compute a Merkle proof for a specific entry.

        Returns the list of sibling hashes needed to verify
        that the entry is part of the log.
        """
        if not self._entries:
            return []

        leaves = [entry.entry_hash for entry in self._entries]
        idx = sequence - 1  # 0-indexed

        if idx < 0 or idx >= len(leaves):
            return []

        # Build tree layers
        proof = []
        level = leaves[:]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])  # Duplicate last for odd lengths

            sibling_idx = idx ^ 1  # XOR 1 flips even↔odd
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])

            # Compute parent level
            parent = []
            for i in range(0, len(level), 2):
                combined = level[i] + level[i + 1]
                parent.append(hashlib.sha256(combined.encode()).hexdigest())

            idx //= 2
            level = parent

        return proof

    def verify_merkle(self, expected_root: Optional[str] = None) -> dict[str, Any]:
        """
        Verify the Merkle tree integrity.

        If expected_root is provided, compares against it.
        Otherwise computes and returns the current root.
        """
        current_root = self.compute_merkle_root()
        result = {
            "valid": True,
            "merkle_root": current_root,
            "entry_count": len(self._entries),
        }

        if expected_root and current_root != expected_root:
            result["valid"] = False
            result["reason"] = f"Merkle root mismatch: expected {expected_root[:16]}..., got {current_root[:16]}..."

        return result

    @staticmethod
    def _merkle_root(leaves: list[str]) -> str:
        """Compute Merkle root from a list of leaf hashes."""
        if not leaves:
            return hashlib.sha256(b"EMPTY_LOG").hexdigest()

        level = leaves[:]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])  # Duplicate last for odd lengths

            parent = []
            for i in range(0, len(level), 2):
                combined = level[i] + level[i + 1]
                parent.append(hashlib.sha256(combined.encode()).hexdigest())

            level = parent

        return level[0]

    # ─── Query ─────────────────────────────────────────────────────────────

    def query(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        event_contains: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
        sort_order: str = "desc",  # "asc" or "desc"
    ) -> list[dict]:
        """Query the audit log with filters and pagination."""
        results = []

        entries = self._entries if sort_order == "asc" else reversed(self._entries)

        skip_count = 0
        for entry in entries:
            if len(results) >= limit:
                break

            if category and entry.category != category:
                continue
            if severity and entry.severity != severity:
                continue
            if agent_id and entry.agent_id != agent_id:
                continue
            if event_contains and event_contains.lower() not in entry.event.lower():
                continue
            if since and entry.timestamp < since:
                if sort_order == "asc":
                    continue
                break  # Since we're iterating reversed for desc, below since means done
            if until and entry.timestamp > until:
                if sort_order == "desc":
                    continue
                break

            if skip_count < offset:
                skip_count += 1
                continue

            results.append(entry.to_dict())

        return results

    def get_critical_events(self, limit: int = 50) -> list[dict]:
        """Get all CRITICAL severity events."""
        return self.query(severity="critical", limit=limit)

    def get_recent(self, seconds: float = 3600, limit: int = 100) -> list[dict]:
        """Get events from the last N seconds."""
        since = time.time() - seconds
        return self.query(since=since, limit=limit)

    # ─── Persistence ──────────────────────────────────────────────────────

    def export_jsonl(self, path: str, mode: str = "w"):
        """
        Export the full log as JSON Lines.

        Args:
            path: Output file path
            mode: "w" (overwrite) or "a" (append)
        """
        from core.security.utils import validate_path
        validated_path = validate_path(self.audit_dir, path, allow_create=True)
        os.makedirs(os.path.dirname(validated_path) if os.path.dirname(validated_path) else ".", exist_ok=True)
        if mode == "a":
            # Append mode: only write the LAST entry (new since last export)
            if self._entries:
                with open(validated_path, "a") as f:
                    f.write(self._entries[-1].to_json() + "\n")
        else:
            # Write/overwrite: write all entries
            with open(validated_path, "w") as f:
                for entry in self._entries:
                    f.write(entry.to_json() + "\n")
        logger.info(f"Audit log exported: {validated_path} ({len(self._entries)} entries)")
        self._dirty = False

    def export_json(self, path: str, include_merkle: bool = True):
        """Export as a single JSON document with optional Merkle root."""
        data = {
            "log_id": self.log_id,
            "entries": [entry.to_dict() for entry in self._entries],
            "statistics": self.statistics(),
        }
        if include_merkle:
            data["merkle_root"] = self.compute_merkle_root()

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Audit log exported as JSON: {path} ({len(self._entries)} entries)")

    def export_incremental(self, path: str):
        """
        Incremental export — only appends new entries since last export.
        Tracks state via the last exported sequence number stored alongside the file.
        """
        tracker_path = path + ".seq"
        last_exported = 0
        try:
            with open(tracker_path) as f:
                last_exported = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            pass

        new_entries = [e for e in self._entries if e.sequence > last_exported]
        if not new_entries:
            return

        from core.security.utils import validate_path
        validated_path = validate_path(self.audit_dir, path, allow_create=True)
        os.makedirs(os.path.dirname(validated_path) if os.path.dirname(validated_path) else ".", exist_ok=True)
        with open(validated_path, "a") as f:
            for entry in new_entries:
                f.write(entry.to_json() + "\n")

        # Update tracker
        with open(tracker_path, "w") as f:
            f.write(str(self._entries[-1].sequence))

        logger.info(f"Audit log incremental: appended {len(new_entries)} entries to {validated_path}")

    def import_jsonl(self, path: str) -> bool:
        """
        Import and verify a JSONL audit log.
        Entries are validated inline (not bulk-loaded) to prevent
        race conditions with tampered data.
        Returns True if chain is valid.
        """
        from core.security.utils import validate_path
        try:
            validated_path = validate_path(self.audit_dir, path)
        except ValueError:
            logger.error(f"Import path escapes audit directory: {path}")
            return False

        try:
            with open(validated_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)

                    # Validate entry structure immediately
                    required_fields = {"timestamp", "category", "severity", "event", "prev_hash", "entry_hash", "sequence"}
                    if not required_fields.issubset(data.keys()):
                        logger.error(f"Import: entry {line_num} missing required fields")
                        return False

                    # Limit details dict size (prevent memory exhaustion)
                    details = data.get("details", {})
                    if isinstance(details, dict) and len(str(details)) > 10000:
                        logger.error(f"Import: entry {line_num} details too large")
                        return False

                    entry = AuditEntry(
                        timestamp=data["timestamp"],
                        category=data["category"],
                        severity=data["severity"],
                        event=data["event"],
                        agent_id=data.get("agent_id"),
                        task_id=data.get("task_id"),
                        details=details,
                        prev_hash=data["prev_hash"],
                        entry_hash=data["entry_hash"],
                        sequence=data["sequence"],
                    )

                    # Inline verification: check chain linkage immediately
                    if entry.sequence != len(self._entries) + 1:
                        logger.error(f"Import: sequence gap at entry {line_num} (expected {len(self._entries) + 1}, got {entry.sequence})")
                        return False
                    if entry.prev_hash != self.last_hash:
                        logger.error(f"Import: chain broken at entry {line_num}")
                        return False
                    # Verify hash wasn't tampered
                    expected_hash = entry.compute_hash()
                    if entry.entry_hash != expected_hash:
                        logger.error(f"Import: hash mismatch at entry {line_num} (tampered)")
                        return False

                    self._entries.append(entry)
                    self._index[entry.sequence] = len(self._entries) - 1

            # Final chain verification (should be redundant with inline checks)
            result = self.verify_chain()
            if not result["valid"]:
                logger.error(f"Imported log verification failed: {result['reason']}")
                self._entries.clear()
                self._index.clear()
                return False

            logger.info(f"Audit log imported: {len(self._entries)} entries, chain valid")
            return True
        except json.JSONDecodeError as e:
            logger.error(f"Import: invalid JSON at line: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to import audit log: {e}")
            return False

    # ─── Stats ─────────────────────────────────────────────────────────────

    def statistics(self) -> dict:
        """Get statistics about the audit log."""
        if not self._entries:
            return {"total": 0}

        categories = {}
        severities = {}
        events = {}
        agent_activity = {}
        for entry in self._entries:
            categories[entry.category] = categories.get(entry.category, 0) + 1
            severities[entry.severity] = severities.get(entry.severity, 0) + 1
            events[entry.event] = events.get(entry.event, 0) + 1
            if entry.agent_id:
                agent_activity[entry.agent_id] = agent_activity.get(entry.agent_id, 0) + 1

        return {
            "total": len(self._entries),
            "categories": categories,
            "severities": severities,
            "top_events": dict(sorted(events.items(), key=lambda x: -x[1])[:10]),
            "top_agents": dict(sorted(agent_activity.items(), key=lambda x: -x[1])[:10]),
            "merkle_root": self.compute_merkle_root(),
            "time_range": {
                "first": self._entries[0].timestamp,
                "last": self._entries[-1].timestamp,
                "duration_hours": round((self._entries[-1].timestamp - self._entries[0].timestamp) / 3600, 2),
            },
        }

    def critical_rate(self, window_seconds: float = 3600) -> float:
        """Get the rate of CRITICAL events per hour in the time window."""
        criticals = self.get_critical_events(limit=10000)
        window_cutoff = time.time() - window_seconds
        recent_criticals = [e for e in criticals if e["timestamp"] >= window_cutoff]
        return round(len(recent_criticals) / (window_seconds / 3600), 2)
