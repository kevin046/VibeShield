"""
Seccomp Profile Generator — Restrict Linux syscalls per container.

Generates Podman-compatible seccomp JSON profiles that restrict
the syscalls available inside containers. Supports two modes:

1. **Default-deny** (from-scratch): starts from an empty allowlist,
   adds only what's needed. Eliminates entire classes of container
   escape techniques (ptrace, mount, keyctl, etc.) at the kernel level.

2. **Default-allow hardening** (from existing profile): starts from
   Podman's working default profile and adds SCMP_ACT_KILL rules for
   dangerous syscalls. This is the recommended approach for production
   — avoids the syscall whack-a-mole that default-deny causes with
   complex runtimes (Rust/tokio, Go, Node.js).
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
    SCMP_ACT_ERRNO = "SCMP_ACT_ERRNO"        # Return errno
    SCMP_ACT_TRACE = "SCMP_ACT_TRACE"        # Notify tracer
    SCMP_ACT_ALLOW = "SCMP_ACT_ALLOW"        # Allow the syscall
    SCMP_ACT_LOG = "SCMP_ACT_LOG"            # Log but allow (audit mode)


class SeccompArch(Enum):
    """Supported architectures."""
    SCMP_ARCH_X86_64 = "SCMP_ARCH_X86_64"
    SCMP_ARCH_AARCH64 = "SCMP_ARCH_AARCH64"
    SCMP_ARCH_X86 = "SCMP_ARCH_X86"
    SCMP_ARCH_X32 = "SCMP_ARCH_X32"


# ─── Architecture mapping with sub-architectures ──────────────────────────────
# Podman/libseccomp uses archMap with subArchitectures to match related ISAs.
ARCH_MAP = [
    {
        "architecture": "SCMP_ARCH_X86_64",
        "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
    },
    {
        "architecture": "SCMP_ARCH_AARCH64",
        "subArchitectures": ["SCMP_ARCH_ARM"],
    },
]


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

# Dangerous syscalls to KILL when hardening an existing allowlist profile.
# These are things Podman's default allows but should be blocked for agent
# containers running untrusted code.
HARDEN_KILL_SYSCALLS = frozenset({
    # Kernel module loading — prevent rootkits
    "init_module", "finit_module", "delete_module",
    # Process injection — prevent debugging/attacking other processes
    "ptrace", "process_vm_readv", "process_vm_writev",
    # Key management — prevent credential theft from kernel keyring
    "keyctl", "request_key", "add_key",
    # BPF — prevent network sniffing and kernel exploitation
    "bpf",
    # Performance monitoring — prevent side-channel attacks
    "perf_event_open",
    # Reboot — prevent container from rebooting host
    "reboot",
    # Mount — prevent filesystem manipulation
    "mount", "mount_setattr", "move_mount", "umount2",
    "pivot_root", "open_tree", "fspick", "fsopen", "fsconfig", "fsmount",
    # Swap — prevent memory manipulation
    "swapon", "swapoff",
    # Kexec — prevent kernel replacement
    "kexec_load", "kexec_file_load",
})


class SeccompProfile:
    """
    Generates a Podman-compatible seccomp profile.

    Two modes of operation:

    **Default-deny** (from-scratch):
        profile = SeccompProfile()
        profile.add_syscalls(AGENT_MINIMAL_SYSCALLS)
        profile.save("/tmp/seccomp-agent.json")

    **Default-allow hardening** (recommended for production):
        profile = SeccompProfile.from_podman_default()
        profile.save("/tmp/seccomp-hardened.json")

    The hardened mode starts from Podman's tested default profile (which
    correctly allows all syscalls needed by common runtimes) and adds
    SCMP_ACT_KILL rules for dangerous syscalls. This avoids the syscall
    whack-a-mole that default-deny causes with complex runtimes.
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
        self._blocked_specific: dict[str, dict] = {}
        self._architectures = architectures or [
            SeccompArch.SCMP_ARCH_X86_64,
            SeccompArch.SCMP_ARCH_AARCH64,
        ]
        self._arch_map = ARCH_MAP

    @classmethod
    def from_podman_default(cls, profile_name: str = "vibeshield-hardened") -> "SeccompProfile":
        """
        Create a profile by hardening Podman's default seccomp profile.

        Starts from the working default that ships with Podman/containers
        and adds SCMP_ACT_KILL rules for dangerous syscalls. This is the
        recommended approach for production — it avoids the syscall
        whack-a-mole that default-deny profiles cause with complex runtimes
        (Rust/tokio, Go, Node.js, etc.).

        The default profile location is /usr/share/containers/seccomp.json.

        Returns:
            SeccompProfile with the hardened configuration.
        """
        podman_default = "/usr/share/containers/seccomp.json"
        if not os.path.exists(podman_default):
            raise FileNotFoundError(
                f"Podman default seccomp profile not found at {podman_default}. "
                "Ensure Podman is installed, or use from_scratch() mode."
            )

        with open(podman_default) as f:
            profile_data = json.load(f)

        instance = cls(
            profile_name=profile_name,
            default_action=SeccompAction(profile_data["defaultAction"]),
        )

        # Store the raw profile for hardening
        instance._base_profile = profile_data
        instance._mode = "harden"

        # Pick up archMap if present
        if "archMap" in profile_data:
            instance._arch_map = profile_data["archMap"]

        return instance

    def add_syscalls(self, syscalls: set[str] | frozenset[str] | list[str]):
        """Add syscalls to the allowlist (after checking blocklist)."""
        for syscall in syscalls:
            if syscall in BLOCKLIST_SYSCALLS:
                logger.warning(f"Blocked dangerous syscall from allowlist: {syscall}")
                continue
            self._allowed_syscalls.add(syscall)

    def block_syscall(self, syscall: str, errno: int = 1, action: str = "SCMP_ACT_KILL"):
        """
        Explicitly block a syscall.

        Args:
            syscall: Name of the syscall to block.
            errno: Errno value to return (only used if action is SCMP_ACT_ERRNO).
            action: Seccomp action (SCMP_ACT_KILL or SCMP_ACT_ERRNO).

        Note:
            For SCMP_ACT_KILL, no args are needed — the syscall is killed
            unconditionally when invoked. For SCMP_ACT_ERRNO, the errno is
            returned to the caller.
        """
        rule = {
            "action": action,
            "args": [],
            "comment": f"Blocked by VibeShield: {syscall}",
        }
        if action == "SCMP_ACT_ERRNO":
            rule["errnoRet"] = errno
        self._blocked_specific[syscall] = rule

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
        """
        Generate the seccomp profile as a dictionary.

        For default-deny (from-scratch) mode, produces a profile with
        explicit ALLOW rules for whitelisted syscalls and KILL for
        blocklisted syscalls.

        For harden mode (from_podman_default), produces the Podman
        default profile with additional KILL rules prepended.
        """
        if getattr(self, "_mode", None) == "harden":
            return self._to_dict_harden()

        return self._to_dict_default_deny()

    def _to_dict_default_deny(self) -> dict:
        """Default-deny profile from scratch."""
        rules = []

        # Always-block rules (highest priority)
        for syscall in BLOCKLIST_SYSCALLS:
            rules.append({
                "names": [syscall],
                "action": "SCMP_ACT_KILL",
                "args": [],
                "comment": f"Always-blocked: {syscall}",
                "includes": {},
                "excludes": {},
            })

        # Explicitly blocked overrides
        for syscall, rule in self._blocked_specific.items():
            entry = {
                "names": [syscall],
                "action": rule["action"],
                "args": rule.get("args", []),
                "comment": rule.get("comment", f"Blocked: {syscall}"),
                "includes": {},
                "excludes": {},
            }
            if "errnoRet" in rule:
                entry["errnoRet"] = rule["errnoRet"]
            rules.append(entry)

        # Allowed syscalls
        allowed = sorted(self._allowed_syscalls - BLOCKLIST_SYSCALLS)
        for syscall in allowed:
            if syscall not in self._blocked_specific:
                action = "SCMP_ACT_LOG" if self.audit_mode else "SCMP_ACT_ALLOW"
                rules.append({
                    "names": [syscall],
                    "action": action,
                    "args": [],
                    "includes": {},
                    "excludes": {},
                })

        return {
            "defaultAction": "SCMP_ACT_LOG" if self.audit_mode else self.default_action.value,
            "defaultErrnoRet": 1,  # EPERM
            "architectures": [a.value for a in self._architectures],
            "syscalls": rules,
        }

    def _to_dict_harden(self) -> dict:
        """
        Hardened profile: Podman default + KILL rules for dangerous syscalls.

        KILL rules are inserted first (highest priority) so they take
        precedence over the default profile's ALLOW rules.
        """
        import copy
        profile = copy.deepcopy(self._base_profile)

        # Collect syscalls to kill
        kill_names = set(HARDEN_KILL_SYSCALLS)
        # Also add any explicitly blocked syscalls
        for syscall, rule in self._blocked_specific.items():
            if rule["action"] == "SCMP_ACT_KILL":
                kill_names.add(syscall)

        kill_rule = {
            "names": sorted(kill_names),
            "action": "SCMP_ACT_KILL",
            "args": [],
            "comment": "VibeShield: dangerous syscalls blocked",
            "includes": {},
            "excludes": {},
        }

        # Insert KILL rules first (highest priority in libseccomp evaluation)
        profile["syscalls"].insert(0, kill_rule)

        # Add any ERRNO-blocked rules after KILL but before ALLOW
        errno_rules = []
        for syscall, rule in self._blocked_specific.items():
            if rule["action"] == "SCMP_ACT_ERRNO":
                entry = {
                    "names": [syscall],
                    "action": "SCMP_ACT_ERRNO",
                    "args": [],
                    "comment": rule.get("comment", f"Blocked: {syscall}"),
                    "errnoRet": rule.get("errnoRet", 1),
                    "includes": {},
                    "excludes": {},
                }
                errno_rules.append(entry)
        for rule in errno_rules:
            profile["syscalls"].insert(1, rule)

        return profile

    def to_json(self, indent: int = 2) -> str:
        """Generate the seccomp profile as JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str, base_dir: str = "/var/lib/vibeshield/seccomp") -> str:
        """Save the profile to a JSON file. Returns the path."""
        from core.security.utils import validate_path
        validated_path = validate_path(base_dir, path, allow_create=True)
        content = self.to_json()
        os.makedirs(os.path.dirname(validated_path) if os.path.dirname(validated_path) else ".", exist_ok=True)
        with open(validated_path, "w") as f:
            f.write(content)
        logger.info(f"Seccomp profile saved: {validated_path}")
        return validated_path

    @property
    def syscall_count(self) -> int:
        """Number of allowed syscalls (excluding blocklist)."""
        return len(self._allowed_syscalls - BLOCKLIST_SYSCALLS)

    @property
    def blocked_count(self) -> int:
        """Number of blocked/kill syscalls."""
        if getattr(self, "_mode", None) == "harden":
            return len(HARDEN_KILL_SYSCALLS | set(self._blocked_specific.keys()))
        return len(BLOCKLIST_SYSCALLS | set(self._blocked_specific.keys()))

    def audit_diff(self, other: "SeccompProfile") -> dict:
        """Compare two profiles and return the difference."""
        return {
            "added": sorted(other._allowed_syscalls - self._allowed_syscalls),
            "removed": sorted(self._allowed_syscalls - other._allowed_syscalls),
            "common": sorted(self._allowed_syscalls & other._allowed_syscalls),
        }

    def validate(self) -> list[str]:
        """
        Validate the profile for common issues.

        Returns a list of warnings/errors found.
        """
        issues = []
        profile = self.to_dict()

        # Check for empty syscalls list
        if not profile.get("syscalls"):
            issues.append("WARNING: No syscall rules defined — all syscalls will use default action")

        # Check for missing includes/excludes
        for i, rule in enumerate(profile.get("syscalls", [])):
            if "includes" not in rule or "excludes" not in rule:
                issues.append(f"Rule {i} ({rule.get('names', ['?'])[0]}): missing 'includes'/'excludes' fields")

            # Check for args with SCMP_CMP_EQ on value that looks like an errno
            # (this was a bug: block_syscall used errno as a value comparison on arg0)
            for arg in rule.get("args", []):
                if arg.get("op") == "SCMP_CMP_EQ" and arg.get("value", 0) in (1, 2, 13, 38):
                    syscall = rule.get("names", ["?"])[0]
                    issues.append(
                        f"Rule for '{syscall}': suspicious arg comparison (value={arg['value']}). "
                        "If this was intended as an errno return, use 'errnoRet' field instead of args."
                    )

        return issues


# ─── Preset profiles for common agent types ──────────────────────────────────

def minimal_profile() -> SeccompProfile:
    """
    Most restrictive profile — no network, minimal syscalls for Python.

    WARNING: This uses default-deny mode which requires careful syscall
    enumeration. For production use with complex runtimes (Rust, Go, Node.js),
    consider hardened_profile() instead.
    """
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


def hardened_profile() -> SeccompProfile:
    """
    Production-ready hardened profile based on Podman's default.

    Starts from Podman's tested default profile and adds SCMP_ACT_KILL
    rules for 26 dangerous syscalls (ptrace, mount, bpf, kexec, etc.).
    This is the recommended preset for agent containers — it provides
    strong isolation without the syscall enumeration burden of default-deny.

    Requires Podman to be installed (reads /usr/share/containers/seccomp.json).

    Raises:
        FileNotFoundError: If Podman's default seccomp profile is not found.
    """
    p = SeccompProfile.from_podman_default(profile_name="vibeshield-hardened")
    return p
