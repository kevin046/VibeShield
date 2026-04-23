"""
Shared security utilities for input validation and sanitization.
"""

import os
import re
import logging

logger = logging.getLogger("vibeshield.security.utils")


def validate_path(base_dir: str, target_path: str, allow_create: bool = False) -> str:
    """
    Validate that a target path resolves within a base directory.
    Prevents path traversal attacks.

    Args:
        base_dir: The allowed base directory
        target_path: The path to validate
        allow_create: Whether the path is allowed to not exist yet

    Returns:
        The canonical (resolved) absolute path

    Raises:
        ValueError: If the path escapes the base directory
    """
    if not base_dir or not target_path:
        raise ValueError("Base directory and target path must be non-empty")

    # Reject obvious traversal attempts
    if ".." in target_path.split("/"):
        raise ValueError(f"Path traversal detected: {target_path}")

    # Resolve both paths to their canonical form
    real_base = os.path.realpath(base_dir)
    real_target = os.path.realpath(os.path.join(base_dir, target_path))

    # Ensure the target is within the base directory
    if not real_target.startswith(real_base + os.sep) and real_target != real_base:
        raise ValueError(
            f"Path escapes base directory: {target_path} "
            f"(resolves to {real_target}, base is {real_base})"
        )

    if not allow_create and not os.path.exists(real_target):
        raise ValueError(f"Path does not exist: {real_target}")

    return real_target


def validate_identifier(value: str, name: str = "identifier", pattern: str = r"^[a-zA-Z0-9_-]+$"):
    """
    Validate that a string is a safe identifier (no special characters).
    Used for task IDs, agent IDs, workspace IDs, etc.

    Args:
        value: The string to validate
        name: Human-readable name for error messages
        pattern: Regex pattern (default: alphanumeric + underscore + hyphen)

    Raises:
        ValueError: If the value doesn't match the pattern
    """
    if not value:
        raise ValueError(f"{name} must be non-empty")
    if not re.match(pattern, value):
        raise ValueError(
            f"Invalid {name}: {value!r} must match pattern {pattern}"
        )
    if len(value) > 256:
        raise ValueError(f"{name} too long: {len(value)} chars (max 256)")
    return value


def sanitize_env_var_name(name: str) -> str:
    """
    Validate an environment variable name.
    Returns the name if valid, raises ValueError otherwise.
    Blocks dangerous env vars that can alter process execution.
    """
    if not re.match(r"^[A-Z][A-Z0-9_]*$", name):
        raise ValueError(
            f"Invalid env var name: {name!r} (must match [A-Z][A-Z0-9_]*)"
        )
    _DANGEROUS = frozenset({
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "PYTHONPATH",
        "PYTHONSTARTUP", "PYTHONHOME", "PYTHONINSPECT",
        "IFS", "SHELL", "BASH_ENV", "ENV",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    })
    if name in _DANGEROUS:
        raise ValueError(f"Blocked dangerous env var: {name}")
    return name


def sanitize_env_var_value(value: str) -> str:
    """
    Validate an environment variable value.
    Rejects values containing newlines or null bytes.
    """
    if "\n" in value or "\0" in value:
        raise ValueError(
            "Env var value contains forbidden characters (newline or null byte)"
        )
    return value
