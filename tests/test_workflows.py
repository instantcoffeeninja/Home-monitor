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


def test_automerge_and_deploy_workflows_present() -> None:
    automerge = _read(".github/workflows/automerge.yml")
    deploy = _read(".github/workflows/deploy-raspberry-pi.yml")

    assert "enable-pull-request-automerge" in automerge
    assert "workflow_dispatch" in deploy
    assert "concurrency" in deploy
    assert "runs-on: self-hosted" in deploy
    assert "Validate self-hosted runner environment" in deploy
    assert "Deploy locally on Raspberry Pi" in deploy
    assert "PI_APP_PATH: /home/pi/Home-monitor" in deploy
    assert "PI_SERVICE_NAME: home-monitor.service" in deploy
    assert "PI_APP_PORT: 5000" in deploy
    assert "appleboy/ssh-action" not in deploy
    assert "secrets.PI_HOST" not in deploy
    assert "secrets.PI_SSH_KEY" not in deploy
    assert "git status --short" in deploy
    assert "git log --oneline -5" in deploy
    assert "python -m pip install -r requirements.txt" in deploy
    assert "systemctl restart" in deploy
    assert "systemctl is-active --quiet" in deploy
    assert "journalctl -u" in deploy
    assert "LOCAL HEALTH CHECK" in deploy
    assert "for attempt in {1..30}" in deploy
    assert "http://127.0.0.1:${PI_APP_PORT}/health" in deploy
    assert "chromium" not in deploy
    assert "playwright" not in deploy
    assert "deploy-screenshot.png" not in deploy


def test_manual_ssh_test_workflow_matches_deploy_steps() -> None:
    ssh_test = _read(".github/workflows/ssh-connectivity-test.yml")

    assert "workflow_dispatch" in ssh_test
    assert "Validate SSH secret configuration" in ssh_test
    assert "Check TCP connectivity to SSH port" in ssh_test
    assert "appleboy/ssh-action" in ssh_test
    assert "Deploy and restart service over SSH" in ssh_test
    assert "git fetch --all" in ssh_test
    assert "git checkout main" in ssh_test
    assert "git pull --ff-only origin main" in ssh_test
    assert "systemctl restart" in ssh_test
    assert "systemctl is-active --quiet" in ssh_test
