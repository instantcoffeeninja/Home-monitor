from pathlib import Path


CODEX_WORKFLOW_PATH = Path(".github/workflows/codex-autofix.yml")
PR_CHECKS_WORKFLOW_PATH = Path(".github/workflows/pr-checks.yml")


def test_codex_autofix_workflow_does_not_require_openai_api_key():
    workflow = CODEX_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "OPENAI_API_KEY" not in workflow
    assert "Check API key exists" not in workflow


def test_pr_checks_workflow_installs_project_requirements():
    workflow = PR_CHECKS_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "pip install -r requirements.txt" in workflow
