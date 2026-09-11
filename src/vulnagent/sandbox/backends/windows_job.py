"""Windows Job Object backend with fail-closed pre-execution assignment.

This backend enforces process-tree and resource controls only.  A Job Object
does not isolate the network or filesystem, and the metadata intentionally
states those unsupported boundaries.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import time
from pathlib import Path
from typing import Any, List, Optional

from ..policy import SandboxPolicy
from ..result import SandboxResult
from .base import SandboxBackend


_JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_CREATE_SUSPENDED = 0x00000004
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


class _JobApi:
    """Small injectable Win32 boundary used by :class:`WindowsJobBackend`."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Objects are available only on Windows")
        from ctypes import wintypes

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BasicAccountingInformation(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        self._wintypes = wintypes
        self._extended_type = ExtendedLimitInformation
        self._accounting_type = BasicAccountingInformation
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.IsProcessInJob.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        ]
        self._kernel32.IsProcessInJob.restype = wintypes.BOOL
        self._kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self._kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        self._ntdll.NtResumeProcess.restype = ctypes.c_long

    def create(self, policy: SandboxPolicy) -> tuple[Any, list[str], dict[str, int]]:
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = self._extended_type()
        flags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        limits.BasicLimitInformation.ActiveProcessLimit = policy.max_processes
        enforced = ["kill_on_job_close", "active_process_limit"]
        values: dict[str, int] = {"max_processes": policy.max_processes}
        if policy.cpu_time_ms is not None:
            flags |= _JOB_OBJECT_LIMIT_JOB_TIME
            limits.BasicLimitInformation.PerJobUserTimeLimit = policy.cpu_time_ms * 10_000
            enforced.append("job_cpu_time_limit")
            values["cpu_time_ms"] = policy.cpu_time_ms
        if policy.memory_limit_mb is not None:
            limit_bytes = policy.memory_limit_mb * 1024 * 1024
            flags |= _JOB_OBJECT_LIMIT_PROCESS_MEMORY | _JOB_OBJECT_LIMIT_JOB_MEMORY
            limits.ProcessMemoryLimit = limit_bytes
            limits.JobMemoryLimit = limit_bytes
            enforced.extend(["process_memory_limit", "job_memory_limit"])
            values["memory_limit_bytes"] = limit_bytes
        limits.BasicLimitInformation.LimitFlags = flags
        ok = self._kernel32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        )
        if not ok:
            error = ctypes.get_last_error()
            self.close(handle)
            raise ctypes.WinError(error)
        return handle, enforced, values

    def assign(self, job: Any, process_handle: int) -> None:
        handle = self._wintypes.HANDLE(process_handle)
        if not self._kernel32.AssignProcessToJobObject(job, handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def is_assigned(self, job: Any, process_handle: int) -> bool:
        assigned = self._wintypes.BOOL()
        if not self._kernel32.IsProcessInJob(
            self._wintypes.HANDLE(process_handle), job, ctypes.byref(assigned)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(assigned.value)

    def query_limits(self, job: Any) -> dict[str, int]:
        limits = self._extended_type()
        returned = self._wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
            ctypes.byref(returned),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "limit_flags": int(limits.BasicLimitInformation.LimitFlags),
            "active_process_limit": int(
                limits.BasicLimitInformation.ActiveProcessLimit
            ),
            "per_process_cpu_100ns": int(
                limits.BasicLimitInformation.PerProcessUserTimeLimit
            ),
            "per_job_cpu_100ns": int(
                limits.BasicLimitInformation.PerJobUserTimeLimit
            ),
            "process_memory_limit": int(limits.ProcessMemoryLimit),
            "job_memory_limit": int(limits.JobMemoryLimit),
            "structure_bytes": ctypes.sizeof(limits),
            "returned_bytes": int(returned.value),
        }

    def query_accounting(self, job: Any) -> dict[str, int]:
        accounting = self._accounting_type()
        returned = self._wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            job,
            1,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            ctypes.byref(returned),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "total_user_100ns": int(accounting.TotalUserTime),
            "total_kernel_100ns": int(accounting.TotalKernelTime),
            "total_processes": int(accounting.TotalProcesses),
            "active_processes": int(accounting.ActiveProcesses),
            "terminated_processes": int(accounting.TotalTerminatedProcesses),
        }

    def resume(self, process_handle: int) -> None:
        status = self._ntdll.NtResumeProcess(self._wintypes.HANDLE(process_handle))
        if status != 0:
            raise OSError(f"NtResumeProcess failed with NTSTATUS {status:#x}")

    def terminate(self, job: Any, exit_code: int = 1) -> None:
        self._kernel32.TerminateJobObject(job, exit_code)

    def close(self, job: Any) -> None:
        if job:
            self._kernel32.CloseHandle(job)


class WindowsJobBackend(SandboxBackend):
    """Execute an authorized target inside a resource-limited Windows Job.

    The process starts suspended and is resumed only after successful Job
    assignment. Any setup failure terminates the suspended process and returns
    an error; there is no silent fallback to :class:`SubprocessBackend`.
    """

    def __init__(self, api: _JobApi | None = None) -> None:
        self._api = api

    def execute(
        self,
        command: List[str],
        policy: SandboxPolicy,
        work_dir: Optional[Path] = None,
        input_data: bytes = b"",
    ) -> SandboxResult:
        policy.validate()
        started = time.perf_counter()
        metadata: dict[str, Any] = {
            "backend_name": "windows_job",
            "enforced_controls": [],
            "unsupported_controls": [
                "file_size_limit",
                "filesystem_isolation",
                "network_isolation",
            ],
            "network_isolation_enforced": False,
            "filesystem_isolation_enforced": False,
            "degraded": False,
            "fail_closed": True,
        }
        result = SandboxResult(command=list(command), metadata=metadata)
        if not command:
            result.error = "command must not be empty"
            return result
        if os.name != "nt":
            result.error = "Windows Job Objects are unavailable on this platform"
            result.metadata["degraded"] = True
            return result

        job: Any = None
        process: subprocess.Popen[bytes] | None = None
        api = self._api
        try:
            api = api or _JobApi()
            job, enforced, values = api.create(policy)
            result.metadata["enforced_controls"] = enforced
            result.metadata["resource_limits"] = values
            environment = os.environ.copy()
            environment.update(policy.environment)
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(work_dir) if work_dir else None,
                shell=False,
                text=False,
                env=environment,
                # Break away from a permissive host Job first, then attach to
                # our non-breakaway Job before any target instruction runs.
                # If the host forbids breakaway, CreateProcess fails closed.
                creationflags=(
                    _CREATE_SUSPENDED
                    | _CREATE_NEW_PROCESS_GROUP
                    | _CREATE_BREAKAWAY_FROM_JOB
                ),
            )
            api.assign(job, int(process._handle))  # type: ignore[attr-defined]
            if not api.is_assigned(job, int(process._handle)):  # type: ignore[attr-defined]
                raise OSError("process was not assigned to the requested Job Object")
            result.metadata["kernel_limits"] = api.query_limits(job)
            api.resume(int(process._handle))  # type: ignore[attr-defined]
            result.executed = True
            stdout, stderr = self._communicate_with_guards(
                process=process,
                job=job,
                api=api,
                policy=policy,
                input_data=input_data,
                result=result,
            )
            result.stdout = self._decode(stdout)
            result.stderr = self._decode(stderr)
            result.return_code = process.returncode
            result.metadata["job_accounting"] = api.query_accounting(job)
            cpu_limit_100ns = (
                policy.cpu_time_ms * 10_000
                if policy.cpu_time_ms is not None
                else None
            )
            accounting = result.metadata["job_accounting"]
            total_cpu_100ns = (
                accounting["total_user_100ns"]
                + accounting["total_kernel_100ns"]
            )
            if (
                cpu_limit_100ns is not None
                and result.return_code not in (None, 0)
                and total_cpu_100ns >= cpu_limit_100ns
            ):
                result.metadata.setdefault("resource_limit_hit", "cpu_time")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            result.error = f"windows_job_setup_or_execution_failed: {exc}"
            result.metadata["degraded"] = True
            if job is not None and api is not None:
                api.terminate(job, 1)
            elif process is not None:
                try:
                    process.kill()
                except OSError:
                    pass
            if process is not None:
                try:
                    process.communicate(timeout=1)
                except (OSError, subprocess.SubprocessError):
                    pass
        finally:
            if job is not None and api is not None:
                api.close(job)
            result.duration_ms = (time.perf_counter() - started) * 1000.0

        result.crashed = (
            result.executed
            and not result.timed_out
            and "resource_limit_hit" not in result.metadata
            and result.return_code is not None
            and result.return_code != 0
        )
        if policy.collect_runtime_trace:
            result.runtime_trace = self._runtime_trace(result)
        return result

    @staticmethod
    def _communicate_with_guards(
        *,
        process: subprocess.Popen[bytes],
        job: Any,
        api: _JobApi,
        policy: SandboxPolicy,
        input_data: bytes,
        result: SandboxResult,
    ) -> tuple[bytes, bytes]:
        """Capture output while enforcing wall and aggregate Job CPU budgets.

        Windows applies the configured Job time limit, while this accounting
        guard also observes nested/packaged-process environments where delivery
        of the automatic limit notification can be delayed.  Termination still
        targets the complete Job rather than only the root PID.
        """

        deadline = time.perf_counter() + policy.timeout_ms / 1000.0
        cpu_limit_100ns = (
            policy.cpu_time_ms * 10_000
            if policy.cpu_time_ms is not None
            else None
        )
        pending_input: bytes | None = input_data
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                result.timed_out = True
                api.terminate(job, 1)
                return process.communicate()
            try:
                return process.communicate(
                    input=pending_input,
                    timeout=min(0.05, remaining),
                )
            except subprocess.TimeoutExpired:
                pending_input = None
                if cpu_limit_100ns is None:
                    continue
                accounting = api.query_accounting(job)
                total_cpu_100ns = (
                    accounting["total_user_100ns"]
                    + accounting["total_kernel_100ns"]
                )
                if total_cpu_100ns >= cpu_limit_100ns:
                    result.metadata["resource_limit_hit"] = "cpu_time"
                    result.metadata["cpu_at_termination_100ns"] = total_cpu_100ns
                    api.terminate(job, 1)
                    return process.communicate()

    @staticmethod
    def _decode(value: bytes | str | None) -> str:
        if value is None:
            return ""
        return value.decode(errors="replace") if isinstance(value, bytes) else value

    @staticmethod
    def _runtime_trace(result: SandboxResult) -> list[str]:
        trace = ["sandbox_backend=windows_job"]
        trace.extend(
            f"enforced_control={name}"
            for name in result.metadata.get("enforced_controls", [])
        )
        trace.extend(
            [
                "network_isolation_enforced=false",
                "filesystem_isolation_enforced=false",
            ]
        )
        if not result.executed:
            trace.extend(["process_launch_failed", f"error={result.error}"])
        else:
            trace.append("process_started")
            if result.timed_out:
                trace.append("timeout")
            elif result.metadata.get("resource_limit_hit"):
                trace.append(
                    f"resource_limit_hit={result.metadata['resource_limit_hit']}"
                )
            elif result.crashed:
                trace.append("process_crashed")
            elif result.return_code == 0:
                trace.append("process_completed")
            else:
                trace.append("process_failed")
            trace.append(f"return_code={result.return_code}")
        trace.append(f"duration_ms={result.duration_ms:.2f}")
        return trace
