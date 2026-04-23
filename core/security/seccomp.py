"""
Seccomp Profile Generator — Restrict Linux syscalls per container.

Generates Podman-compatible seccomp JSON profiles that whitelist only
the syscalls an AI agent actually needs. Every other syscall is blocked.

Default-deny approach: starts from an empty allowlist, adds only what's needed.
This eliminates entire classes of container escape techniques (ptrace, mount,
keyctl, userfaultfd, etc.) at the kernel level.
"""

import json
import logging
import os
from enum import Enum
from typing import Optional

logger = logging.getLogger("vibeshield.security.seccomp")


class SeccompAction(Enum):
    """Seccomp rule actions."""
    SCMP_ACT_KILL = "SCMP_ACT_KILL"          # Kill the process (strictest)
    SCMP_ACT_ERRNO = "SCMP_ACT_ERRNO"        # Return EPERM
    SCMP_ACT_TRACE = "SCMP_ACT_TRACE"        # Notify tracer
    SCMP_ACT_ALLOW = "SCMP_ACT_ALLOW"        # Allow the syscall
    SCMP_ACT_LOG = "SCMP_ACT_LOG"            # Log but allow (audit mode)


class SeccompArch(Enum):
    """Supported architectures."""
    SCMP_ARCH_X86_64 = "SCMP_ARCH_X86_64"
    SCMP_ARCH_AARCH64 = "SCMP_ARCH_AARCH64"
    SCMP_ARCH_X86 = "SCMP_ARCH_X86"
    SCMP_ARCH_X32 = "SCMP_ARCH_X32"


# Minimal syscall set for Python agent execution
# These are the ONLY syscalls permitted — everything else is blocked
AGENT_MINIMAL_SYSCALLS = frozenset({
    # Process lifecycle
    "read", "write", "close", "fstat", "fstat64",
    "lseek", "lseek64", "mmap", "mmap2", "munmap",
    "brk", "sbrk",
    # File I/O
    "open", "openat", "open64", "openat64",
    "readlink", "readlinkat", "faccessat", "faccessat2",
    "stat", "stat64", "lstat", "lstat64", "newfstatat",
    "getdents", "getdents64",
    # Memory management
    "mprotect", "mremap", "mincore",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "sigaltstack",
    # Network (only if explicitly enabled)
    "socket", "connect", "sendto", "recvfrom", "recvmsg", "sendmsg",
    "shutdown", "getsockname", "getpeername",
    "poll", "ppoll", "select", "pselect6",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
    # Threading
    "futex", "clone", "clone3", "set_tid_address",
    "gettid",
    "sched_yield", "sched_getaffinity",
    # Time
    "clock_gettime", "clock_getres", "gettimeofday",
    "nanosleep",
    # Resource info
    "getrlimit", "getrusage",
    "uname", "getpid", "getppid", "getuid", "getgid",
    "geteuid", "getegid", "getgroups",
    # Exit
    "exit", "exit_group",
    # Pipe / IPC (limited)
    "pipe", "pipe2", "eventfd", "eventfd2",
    "dup", "dup2", "dup3",
    # DLOpen (Python imports)
    "statx",
})

# Syscalls that are ALWAYS blocked — never whitelist these regardless of profile
BLOCKLIST_SYSCALLS = frozenset({
    # Container escape vectors
    "ptrace", "process_vm_readv", "process_vm_writev",
    "userfaultfd",
    # Mount / filesystem manipulation
    "mount", "umount", "umount2", "pivot_root",
    "pivot_root",
    # Kernel manipulation
    "kexec_load", "kexec_file_load",
    "reboot", "sethostname", "setdomainname",
    "init_module", "finit_module", "delete_module",
    # Key management (credential theft)
    "keyctl", "add_key", "request_key",
    # Capabilities manipulation
    "capset", "capget",
    # Namespace manipulation
    "unshare", "setns",
    # BPF (can bypass network filters)
    "bpf", "perf_event_open",
    # Raw I/O
    "iopl", "ioperm",
    # System configuration
    "syslog", "acct",
    "personality",
})


class SeccompProfile:
    """
    Generates a Podman-compatible seccomp profile.

    Usage:
        profile = SeccompProfile(profile_name="agent-restricted")
        profile.add_syscalls(AGENT_MINIMAL_SYSCALLS)
        json_path = profile.save("/tmp/seccomp-agent.json")
        # Then: podman run --security-opt seccomp=/tmp/seccomp-agent.json ...
    """

    def __init__(
        self,
        profile_name: str = "vibeshield-agent",
        default_action: SeccompAction = SeccompAction.SCMP_ACT_ERRNO,
        architectures: Optional[list[SeccompArch]] = None,
        audit_mode: bool = False,
    ):
        self.profile_name = profile_name
        self.default_action = default_action
        self.audit_mode = audit_mode
        self._allowed_syscalls: set[str] = set()
        self._blocked_specific: dict[str, dict] = {}  # syscall -> override rule
        self._architectures = architectures or [
            SeccompArch.SCMP_ARCH_X86_64,
            SeccompArch.SCMP_ARCH_AARCH64,
        ]

    def add_syscalls(self, syscalls: set[str] | frozenset[str] | list[str]):
        """Add syscalls to the allowlist (after checking blocklist)."""
        for syscall in syscalls:
            if syscall in BLOCKLIST_SYSCALLS:
                logger.warning(f"Blocked dangerous syscall from allowlist: {syscall}")
                continue
            self._allowed_syscalls.add(syscall)

    def block_syscall(self, syscall: str, errno: int = 1):
        """
        Explicitly block a syscall with a specific errno.
        Takes priority over the allowlist.
        """
        self._blocked_specific[syscall] = {
            "action": "SCMP_ACT_ERRNO",
            "args": [{"index": 0, "op": "SCMP_CMP_EQ", "value": errno}],
        }

    def allow_network(self):
        """Enable network-related syscalls."""
        network_syscalls = {
            "socket", "connect", "sendto", "recvfrom",
            "recvmsg", "sendmsg", "shutdown",
            "getsockname", "getpeername",
            "bind", "listen", "accept", "accept4",
            "setsockopt", "getsockopt",
        }
        self.add_syscalls(network_syscalls)

    def to_dict(self) -> dict:
        """Generate the seccomp profile as a dictionary."""
        rules = []

        # Always-block rules (highest priority)
        for syscall in BLOCKLIST_SYSCALLS:
            rules.append({
                "names": [syscall],
                "action": "SCMP_ACT_KILL",
                "args": [],
                "comment": f"Always-blocked: {syscall}",
            })

        # Explicitly blocked overrides
        for syscall, rule in self._blocked_specific.items():
            rules.append({
                "names": [syscall],
                "action": rule["action"],
                "args": rule.get("args", []),
                "comment": f"Explicitly blocked: {syscall}",
            })

        # Allowed syscalls
        allowed = sorted(self._allowed_syscalls - BLOCKLIST_SYSCALLS)
        for syscall in allowed:
            if syscall not in self._blocked_specific:
                action = "SCMP_ACT_LOG" if self.audit_mode else "SCMP_ACT_ALLOW"
                rules.append({
                    "names": [syscall],
                    "action": action,
                    "args": [],
                })

        return {
            "defaultAction": self.default_action.value if not self.audit_mode else "SCMP_ACT_LOG",
            "defaultErrnoRet": 1,  # EPERM
            "architectures": [a.value for a in self._architectures],
            "syscalls": rules,
        }

    def to_json(self, indent: int = 2) -> str:
        """Generate the seccomp profile as JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str) -> str:
        """Save the profile to a JSON file. Returns the path."""
        content = self.to_json()
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        logger.info(f"Seccomp profile saved: {path} ({len(self._allowed_syscalls)} syscalls allowed)")
        return path

    @property
    def syscall_count(self) -> int:
        """Number of allowed syscalls (excluding blocklist)."""
        return len(self._allowed_syscalls - BLOCKLIST_SYSCALLS)

    def audit_diff(self, other: "SeccompProfile") -> dict:
        """Compare two profiles and return the difference."""
        return {
            "added": sorted(other._allowed_syscalls - self._allowed_syscalls),
            "removed": sorted(self._allowed_syscalls - other._allowed_syscalls),
            "common": sorted(self._allowed_syscalls & other._allowed_syscalls),
        }


# Preset profiles for common agent types

def minimal_profile() -> SeccompProfile:
    """Most restrictive profile — no network, minimal syscalls for Python."""
    p = SeccompProfile(profile_name="vibeshield-minimal")
    p.add_syscalls(AGENT_MINIMAL_SYSCALLS - {
        "socket", "connect", "sendto", "recvfrom",
        "recvmsg", "sendmsg", "shutdown",
        "getsockname", "getpeername",
        "bind", "listen", "accept", "accept4",
        "setsockopt", "getsockopt",
        "poll", "ppoll", "select", "pselect6",
        "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
    })
    return p


def compute_profile() -> SeccompProfile:
    """Profile for compute-heavy agents (no network)."""
    p = minimal_profile()
    p.add_syscalls({"sched_setaffinity", "getcpu"})
    return p


def network_profile() -> SeccompProfile:
    """Profile for agents that need outbound network (audited proxy only)."""
    p = SeccompProfile(profile_name="vibeshield-network")
    p.add_syscalls(AGENT_MINIMAL_SYSCALLS)
    p.allow_network()
    return p
