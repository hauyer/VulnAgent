"""Language registry and file-policy tests for the source parser."""

from vulnagent.analyzers.source.parser.languages import (
    DEFAULT_MAX_FILE_BYTES,
    detect_language,
    is_ignored_directory,
    language_display_name,
    recognized_languages,
)


def test_detects_common_languages_by_extension() -> None:
    assert detect_language("app.py").identifier == "python"  # type: ignore[union-attr]
    assert detect_language("mod.PY").identifier == "python"  # type: ignore[union-attr]
    assert detect_language("main.c").identifier == "c"  # type: ignore[union-attr]
    assert detect_language("lib.h").identifier == "c"  # type: ignore[union-attr]
    assert detect_language("a.hpp").identifier == "cpp"  # type: ignore[union-attr]
    assert detect_language("Main.java").identifier == "java"  # type: ignore[union-attr]
    assert detect_language("index.js").identifier == "javascript"  # type: ignore[union-attr]
    assert detect_language("index.tsx").identifier == "typescript"  # type: ignore[union-attr]
    assert detect_language("go.mod") is None
    assert detect_language("server.go").identifier == "go"  # type: ignore[union-attr]
    assert detect_language("notes.txt") is None
    assert detect_language("LICENSE") is None


def test_only_python_is_flagged_as_structurally_parsed() -> None:
    specs = {
        spec.identifier: spec.structurally_parsed
        for spec in recognized_languages()
    }
    assert specs["python"] is True
    parsed = {identifier for identifier, flag in specs.items() if flag}
    assert parsed == {"python"}


def test_display_name_round_trip() -> None:
    assert language_display_name("python") == "Python"
    assert language_display_name("cpp") == "C++"
    assert language_display_name("unknown_lang") == "unknown_lang"


def test_ignored_directory_policy_is_case_insensitive() -> None:
    for name in (".git", ".venv", "venv", "node_modules", "__pycache__",
                 "build", "dist", ".idea", "target", "htmlcov", ".pytest_cache"):
        assert is_ignored_directory(name), name
        assert is_ignored_directory(name.upper()), name.upper()
    assert not is_ignored_directory("src")
    assert not is_ignored_directory("app")


def test_default_file_limit_is_positive() -> None:
    assert DEFAULT_MAX_FILE_BYTES > 0
