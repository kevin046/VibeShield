"""
Agent Command Protocol — Standardized interface between agents and VibeShield infrastructure.

Agents communicate with the platform through a fixed set of commands.
Each command is validated, logged, and routed to the appropriate layer.
"""

import time
import logging
import json
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

logger = logging.getLogger("vibeshield.api")


class CommandStatus(Enum):
    OK = "ok"
    DENIED = "denied"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class CommandType(Enum):
    # Lifecycle commands
    HEARTBEAT = "HEARTBEAT"
    SIGNAL_COMPLETE = "SIGNAL_COMPLETE"

    # Resource requests
    REQUEST_MEMORY = "REQUEST_MEMORY"
    WEB_SEARCH = "WEB_SEARCH"
    REQUEST_DATA = "REQUEST_DATA"

    # Settlement commands
    ESCROW_RELEASE = "ESCROW_RELEASE"
    STATE_SYNC = "STATE_SYNC"


@dataclass
class AgentCommand:
    """A validated command from an agent to VibeShield platform."""
    command_type: CommandType
    agent_id: str
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    task_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "command": self.command_type.value,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class CommandResponse:
    """Platform response to an agent command."""
    status: CommandStatus
    command_type: CommandType
    agent_id: str
    data: dict = field(default_factory=dict)
    message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "command": self.command_type.value,
            "agent_id": self.agent_id,
            "data": self.data,
            "message": self.message,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class CommandRouter:
    """
    Routes and validates agent commands.

    Every command is logged for audit purposes. Commands are validated
    against the agent's current task state before being forwarded to
    the appropriate VibeShield layer.
    """

    def __init__(self):
        self._handlers: dict[CommandType, callable] = {}
        self._command_log: list[dict] = []

    def register_handler(self, command_type: CommandType, handler: callable):
        """Register a handler function for a command type."""
        self._handlers[command_type] = handler
        logger.debug(f"Handler registered for {command_type.value}")

    def route(self, command: AgentCommand) -> CommandResponse:
        """
        Route a validated command to the appropriate handler.

        All commands are logged before processing.
        """
        # Log the command
        self._log_command(command)

        # Find handler
        handler = self._handlers.get(command.command_type)
        if not handler:
            logger.warning(f"No handler for command: {command.command_type.value}")
            return CommandResponse(
                status=CommandStatus.UNKNOWN,
                command_type=command.command_type,
                agent_id=command.agent_id,
                message=f"Unknown command: {command.command_type.value}",
            )

        # Execute handler
        try:
            result = handler(command)
            return CommandResponse(
                status=CommandStatus.OK,
                command_type=command.command_type,
                agent_id=command.agent_id,
                data=result,
                message="Command executed successfully",
            )
        except PermissionError as e:
            logger.warning(f"Command denied for agent {command.agent_id}: {e}")
            return CommandResponse(
                status=CommandStatus.DENIED,
                command_type=command.command_type,
                agent_id=command.agent_id,
                message="Permission denied",
            )
        except TimeoutError as e:
            return CommandResponse(
                status=CommandStatus.TIMEOUT,
                command_type=command.command_type,
                agent_id=command.agent_id,
                message="Operation timed out",
            )
        except Exception as e:
            logger.error(f"Command handler error: {e}", exc_info=True)
            return CommandResponse(
                status=CommandStatus.DENIED,
                command_type=command.command_type,
                agent_id=command.agent_id,
                message="Internal error",
            )

    def _log_command(self, command: AgentCommand):
        """Log command for audit trail."""
        entry = {
            "command": command.command_type.value,
            "agent_id": command.agent_id,
            "task_id": command.task_id,
            "timestamp": command.timestamp,
        }
        self._command_log.append(entry)
        logger.info(f"Command: {entry}")

    @classmethod
    def parse(cls, raw: str, agent_id: str) -> Optional[AgentCommand]:
        """
        Parse a raw JSON command string into an AgentCommand.

        Expected format:
        {
            "command": "HEARTBEAT",
            "task_id": "...",
            "payload": { ... }
        }
        """
        try:
            data = json.loads(raw)
            command_type = CommandType(data.get("command", "").upper())
            return AgentCommand(
                command_type=command_type,
                agent_id=agent_id,
                task_id=data.get("task_id"),
                payload=data.get("payload", {}),
            )
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.error(f"Failed to parse command: {e}")
            return None


# ── Pre-built command senders (for agent-side usage) ──

def heartbeat(agent_id: str, task_id: str) -> str:
    """Send a heartbeat to prove the agent is still running."""
    return json.dumps({"command": "HEARTBEAT", "task_id": task_id})


def signal_complete(agent_id: str, task_id: str, output_hash: str) -> str:
    """Notify the platform that a task is complete."""
    return json.dumps({
        "command": "SIGNAL_COMPLETE",
        "task_id": task_id,
        "payload": {"output_hash": output_hash},
    })


def request_memory(agent_id: str, task_id: str, bytes_needed: int, reason: str) -> str:
    """Request an extended context window."""
    return json.dumps({
        "command": "REQUEST_MEMORY",
        "task_id": task_id,
        "payload": {"bytes_needed": bytes_needed, "reason": reason},
    })


def web_search(agent_id: str, task_id: str, query: str) -> str:
    """Request a web search through the audited proxy."""
    return json.dumps({
        "command": "WEB_SEARCH",
        "task_id": task_id,
        "payload": {"query": query},
    })


def request_data(agent_id: str, task_id: str, api_url: str, method: str = "GET") -> str:
    """Request data from an external API through the audited proxy."""
    return json.dumps({
        "command": "REQUEST_DATA",
        "task_id": task_id,
        "payload": {"url": api_url, "method": method},
    })


def escrow_release(agent_id: str, task_id: str, bounty_id: str) -> str:
    """Request payment release from escrow."""
    return json.dumps({
        "command": "ESCROW_RELEASE",
        "task_id": task_id,
        "payload": {"bounty_id": bounty_id},
    })


def state_sync(agent_id: str, task_id: str, state: dict) -> str:
    """Sync agent state with the orchestrator."""
    return json.dumps({
        "command": "STATE_SYNC",
        "task_id": task_id,
        "payload": {"state": state},
    })
