from pathlib import Path


WORKFLOW_PATH = Path(".github/workflows/codex-autofix.yml")


def test_codex_autofix_workflow_does_not_require_openai_api_key():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "OPENAI_API_KEY" not in workflow
    assert "Check API key exists" not in workflow
