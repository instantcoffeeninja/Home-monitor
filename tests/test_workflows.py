from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_ci_workflow_has_autofix_and_tests() -> None:
    ci = _read(".github/workflows/ci.yml")
    assert "ruff check . --fix" in ci
    assert "ruff format ." in ci
    assert "python -m pytest -q" in ci


def test_dependabot_tracks_pip_and_actions() -> None:
    dependabot = _read(".github/dependabot.yml")
    assert 'package-ecosystem: "pip"' in dependabot
    assert 'package-ecosystem: "github-actions"' in dependabot


def test_security_automerge_and_deploy_workflows_present() -> None:
    aikido = _read(".github/workflows/aikido-security.yml")
    automerge = _read(".github/workflows/automerge.yml")
    deploy = _read(".github/workflows/deploy-raspberry-pi.yml")

    assert "AikidoSec/github-actions-workflow" in aikido
    assert "enable-pull-request-automerge" in automerge
    assert "appleboy/ssh-action" in deploy
    assert "systemctl restart" in deploy
