"""ProjectImporter tests: path/zip/git origins, safety and parse chaining."""

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from vulnagent.analyzers.source.parser import (
    ProjectImportError,
    ProjectImporter,
    SourceProjectParser,
)
from vulnagent.contracts import ProjectInput

HAS_GIT = shutil.which("git") is not None


def request(project_path: str, **metadata) -> ProjectInput:
    return ProjectInput(
        task_id="task-1",
        target_id="target-1",
        project_path=project_path,
        metadata=metadata,
    )


async def import_project(importer: ProjectImporter, req: ProjectInput, destination: Path | None = None):
    return await importer.import_project(req, destination=destination)


@pytest.mark.asyncio
async def test_local_directory_is_used_in_place(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("def main():\n    pass\n", encoding="utf-8")
    importer = ProjectImporter()

    imported = await import_project(importer, request(str(tmp_path)))

    assert imported.origin_type == "path"
    assert Path(imported.project_path) == tmp_path.resolve()
    assert imported.vcs is None
    assert importer.managed_dirs == ()
    assert (Path(imported.project_path) / "main.py").exists()


@pytest.mark.asyncio
async def test_missing_path_raises(tmp_path: Path) -> None:
    importer = ProjectImporter()
    with pytest.raises(ProjectImportError, match="does not exist"):
        await import_project(importer, request(str(tmp_path / "missing")))


@pytest.mark.asyncio
async def test_git_worktree_detected_without_cloning(tmp_path: Path) -> None:
    if not HAS_GIT:
        pytest.skip("git not available")
    subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "init", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
    importer = ProjectImporter()

    imported = await import_project(importer, request(str(tmp_path)))

    assert imported.origin_type == "path"
    assert imported.vcs == "git"


@pytest.mark.asyncio
async def test_zip_is_extracted_and_parseable(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("proj/main.py", "def run():\n    return 1\n")
        bundle.writestr("proj/notes.txt", "hello\n")
    destination = tmp_path / "out"
    importer = ProjectImporter()

    imported = await import_project(
        importer, request(str(archive)), destination=destination
    )
    result = await SourceProjectParser().analyze(
        request(imported.project_path)
    )

    assert imported.origin_type == "zip"
    assert imported.extracted_to == imported.project_path
    assert (Path(imported.project_path) / "proj" / "main.py").exists()
    assert result.languages == ["python"]
    assert result.files == ["proj/main.py"]
    assert {symbol["qualified_name"] for symbol in result.symbols} == {
        "proj.main.run"
    }


@pytest.mark.asyncio
async def test_zip_slip_entry_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../../evil.py", "print('pwn')\n")
    destination = tmp_path / "out"
    importer = ProjectImporter()

    with pytest.raises(ProjectImportError, match="Unsafe archive member"):
        await import_project(importer, request(str(archive)), destination=destination)
    assert not (tmp_path / "evil.py").exists()


@pytest.mark.asyncio
async def test_extract_size_limit_is_enforced(tmp_path: Path) -> None:
    archive = tmp_path / "big.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("proj/main.py", "x = 1\n")
    importer = ProjectImporter()

    with pytest.raises(ProjectImportError, match="max_extract_bytes"):
        await import_project(
            importer,
            request(str(archive), max_extract_bytes=2),
            destination=tmp_path / "out",
        )


@pytest.mark.asyncio
async def test_managed_destination_is_cleaned_up(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("main.py", "def f():\n    return 1\n")
    importer = ProjectImporter()

    imported = await import_project(importer, request(str(archive)))
    assert importer.managed_dirs
    assert Path(imported.project_path).exists()

    importer.cleanup()

    assert not Path(imported.project_path).exists()
    assert importer.managed_dirs == ()


@pytest.mark.asyncio
async def test_remote_git_clone_is_denied_by_default(tmp_path: Path) -> None:
    importer = ProjectImporter()
    with pytest.raises(ProjectImportError, match="allow_git_clone"):
        await import_project(
            importer,
            request("https://github.com/hauyer/VulnAgent.git"),
            destination=tmp_path / "out",
        )
    assert importer.managed_dirs == ()


@pytest.mark.asyncio
async def test_git_clone_works_when_explicitly_allowed(tmp_path: Path) -> None:
    if not HAS_GIT:
        pytest.skip("git not available")
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "init", str(origin)],
        check=True,
        capture_output=True,
    )
    (origin / "main.py").write_text("def work():\n    return 1\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(origin), "add", "main.py"], check=True, capture_output=True
    )
    subprocess.run(
        [
            "git", "-C", str(origin), "-c", "user.name=test",
            "-c", "user.email=test@example.com", "commit", "-m", "init",
        ],
        check=True,
        capture_output=True,
    )
    importer = ProjectImporter()

    imported = await import_project(
        importer,
        request(origin.as_uri(), allow_git_clone=True),
        destination=tmp_path / "clones",
    )

    assert imported.origin_type == "git"
    assert imported.vcs == "git"
    assert (Path(imported.project_path) / "main.py").exists()
