from pathlib import Path

import pytest

from vulnagent.sandbox.policy import SandboxPolicy


def test_default_policy_is_safe():
    policy = SandboxPolicy()

    assert policy.timeout_ms == 3000
    assert policy.max_processes == 8
    assert policy.max_file_size_mb == 10

    assert policy.network_enabled is False
    assert policy.kill_tree is True
    assert policy.collect_runtime_trace is True


def test_valid_policy_passes_validation():
    policy = SandboxPolicy(
        timeout_ms=5000,
        max_processes=4,
        max_file_size_mb=20,
    )

    policy.validate()


def test_invalid_timeout_is_rejected():
    policy = SandboxPolicy(timeout_ms=0)

    with pytest.raises(ValueError):
        policy.validate()


def test_invalid_process_limit_is_rejected():
    policy = SandboxPolicy(max_processes=0)

    with pytest.raises(ValueError):
        policy.validate()


def test_invalid_file_size_is_rejected():
    policy = SandboxPolicy(max_file_size_mb=0)

    with pytest.raises(ValueError):
        policy.validate()


def test_network_requires_allowed_hosts():
    policy = SandboxPolicy(
        network_enabled=True,
        allowed_hosts=[],
    )

    with pytest.raises(ValueError):
        policy.validate()


def test_allowed_host():
    policy = SandboxPolicy(
        network_enabled=True,
        allowed_hosts=["127.0.0.1"],
    )

    policy.validate()

    assert policy.is_host_allowed("127.0.0.1") is True
    assert policy.is_host_allowed("example.com") is False


def test_network_disabled_blocks_all_hosts():
    policy = SandboxPolicy(
        network_enabled=False,
        allowed_hosts=["127.0.0.1"],
    )

    assert policy.is_host_allowed("127.0.0.1") is False


def test_writable_path():
    root = Path.cwd() / "sandbox_test"

    policy = SandboxPolicy(
        writable_dirs=[root],
    )

    target = root / "output.txt"

    assert policy.is_path_writable(target) is True


def test_unwritable_path():
    root = Path.cwd() / "sandbox_test"
    other = Path.cwd() / "other_directory"

    policy = SandboxPolicy(
        writable_dirs=[root],
    )

    target = other / "output.txt"

    assert policy.is_path_writable(target) is False