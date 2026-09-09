from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class SandboxPolicy:
    """
    Sandbox execution policy.

    This class describes the resource and execution limits
    that should be applied when running a target program.
    """

    # =========================
    # 1. Execution time limit
    # =========================

    timeout_ms: int = 3000

    # =========================
    # 2. Process limits
    # =========================

    max_processes: int = 8

    # Whether child processes should be terminated
    # when the target process is terminated.
    kill_tree: bool = True

    # =========================
    # 3. File limits
    # =========================

    # Maximum size of a single generated file.
    max_file_size_mb: int = 10

    # Directories that the target is allowed to write to.
    writable_dirs: List[Path] = field(default_factory=list)

    # Directories that should be treated as read-only.
    readonly_dirs: List[Path] = field(default_factory=list)

    # =========================
    # 4. Network policy
    # =========================

    # Network access is disabled by default.
    network_enabled: bool = False

    # Explicitly allowed hosts.
    #
    # Example:
    # ["127.0.0.1"]
    #
    # Empty list means no host is explicitly allowed.
    allowed_hosts: List[str] = field(default_factory=list)

    # =========================
    # 5. Environment variables
    # =========================

    # Environment variables passed to the target process.
    environment: Dict[str, str] = field(default_factory=dict)

    # =========================
    # 6. Runtime resource limits
    # =========================

    # Maximum CPU time in milliseconds.
    cpu_time_ms: Optional[int] = None

    # Maximum memory usage in MB.
    memory_limit_mb: Optional[int] = None

    # =========================
    # 7. Runtime trace
    # =========================

    # Whether runtime information should be collected.
    collect_runtime_trace: bool = True

    # =========================
    # Validation
    # =========================

    def validate(self) -> None:
        """
        Validate the sandbox policy.

        Raises:
            ValueError: if a policy value is invalid.
        """

        if self.timeout_ms <= 0:
            raise ValueError("timeout_ms must be greater than 0")

        if self.max_processes <= 0:
            raise ValueError("max_processes must be greater than 0")

        if self.max_file_size_mb <= 0:
            raise ValueError("max_file_size_mb must be greater than 0")

        if self.cpu_time_ms is not None and self.cpu_time_ms <= 0:
            raise ValueError("cpu_time_ms must be greater than 0")

        if self.memory_limit_mb is not None and self.memory_limit_mb <= 0:
            raise ValueError("memory_limit_mb must be greater than 0")

        # Network should not be enabled while there are
        # no explicitly allowed hosts.
        if self.network_enabled and not self.allowed_hosts:
            raise ValueError(
                "network_enabled=True requires at least one allowed host"
            )

    # =========================
    # Utility methods
    # =========================

    def is_host_allowed(self, host: str) -> bool:
        """
        Check whether a network host is explicitly allowed.
        """

        if not self.network_enabled:
            return False

        return host in self.allowed_hosts

    def is_path_writable(self, path: Path) -> bool:
        """
        Check whether a path is inside one of the writable directories.
        """

        try:
            resolved_path = path.resolve()
        except OSError:
            return False

        for directory in self.writable_dirs:
            try:
                resolved_directory = directory.resolve()

                resolved_path.relative_to(resolved_directory)
                return True

            except ValueError:
                continue
            except OSError:
                continue

        return False