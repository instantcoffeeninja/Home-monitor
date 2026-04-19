from pathlib import Path


def _section(text: str, title: str, next_title: str) -> str:
    start = text.index(title) + len(title)
    end = text.index(next_title)
    return text[start:end]


def test_ready_contains_reset_implemented_features() -> None:
    text = Path("features.md").read_text(encoding="utf-8")
    ready = _section(text, "## [READY]", "## [BACKLOG]")

    for feature_id in ["HM-003", "HM-004", "HM-005", "HM-006", "HM-007", "HM-008"]:
        assert feature_id in ready


def test_done_is_empty_after_reset() -> None:
    text = Path("features.md").read_text(encoding="utf-8")
    done = text.split("## [DONE]", maxsplit=1)[1]

    assert "_No features marked done in this reset list._" in done
    for feature_id in ["HM-003", "HM-004", "HM-005", "HM-006", "HM-007", "HM-008"]:
        assert feature_id not in done


def test_suggested_files_use_flask_project_paths() -> None:
    text = Path("features.md").read_text(encoding="utf-8")

    assert "server.py" not in text
    assert "templates/index.html" not in text
    assert "home_monitor.db" not in text

    assert "src/home_monitor/app.py" in text
    assert "src/home_monitor/core.py" in text
    assert "tests/test_app.py" in text
