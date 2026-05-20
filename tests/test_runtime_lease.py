from pathlib import Path

import pytest

from bpfw.protection import runtime_lease
from bpfw.errors import BlueprintLockedError


def test_init_requires_interactive_approval_when_protected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime_lease, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(
        runtime_lease,
        "get_authority_protection_status",
        lambda project_root: type("ProtectionStatus", (), {"status": "locked"})(),
    )

    with runtime_lease.runtime_blueprint_write_lease(
        project_root=tmp_path,
        tool_name="init",
        input_func=lambda prompt: "y",
    ) as lease:
        assert lease.temporarily_unlocked is True


def test_unknown_tool_does_not_request_protected_write_lease(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime_lease, "_is_interactive_terminal", lambda: False)

    with runtime_lease.runtime_blueprint_write_lease(
        project_root=tmp_path,
        tool_name="unknown",
        input_func=lambda prompt: "n",
    ) as lease:
        assert lease.temporarily_unlocked is False


def test_reshard_requires_interactive_terminal_when_protected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime_lease, "_is_interactive_terminal", lambda: False)
    monkeypatch.setattr(
        runtime_lease,
        "get_authority_protection_status",
        lambda project_root: type("ProtectionStatus", (), {"status": "locked"})(),
    )

    with pytest.raises(BlueprintLockedError):
        with runtime_lease.runtime_blueprint_write_lease(
            project_root=tmp_path,
            tool_name="reshard",
            input_func=lambda prompt: "y",
        ):
            pass
