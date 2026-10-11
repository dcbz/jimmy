"""CLI-level tests: startup validation and --watch error surfacing.

The auth check exists because the SDK only validates credentials when it
builds the first request — under --watch that turned a missing
ANTHROPIC_API_KEY into a crash inside the agent thread with a traceback
nobody could read (see runs/*/error.log of the run that motivated this).
"""

import types

import pytest

from jimmy import cli
from jimmy.agent import Harness
from jimmy.tui import TEXTUAL


class FakeClient(types.SimpleNamespace):
    pass


# ------------------------------------------------------------- fail fast auth

def test_run_without_credentials_exits_before_touching_anything(
        monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key=None, auth_token=None,
                                               credentials=None))
    monkeypatch.setattr(cli, "build_target",
                        lambda *a, **k: calls.append(a) or None)
    rc = cli.main(["run", "--target", "demo", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    assert rc == 2
    assert "credentials" in capsys.readouterr().err
    assert calls == []                        # no target, no lab, no run dir
    assert not (tmp_path / "r").exists()


def test_gateway_without_model_override_gets_startup_hint(
        monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key="sk-test",
                                                auth_token=None,
                                                credentials=None))
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://gateway.invalid:18300")
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.setattr(Harness, "run",
                        lambda self: {"status": "no_findings",
                                      "false_positive": False,
                                      "verifier_verdict": {}, "metrics": {},
                                      "narrative": "patched"})
    rc = cli.main(["run", "--target", "demo", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    assert rc == 0
    assert "ANTHROPIC_MODEL" in capsys.readouterr().err


def test_no_gateway_hint_on_official_endpoint(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key="sk-test",
                                                auth_token=None,
                                                credentials=None))
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.setattr(Harness, "run",
                        lambda self: {"status": "no_findings",
                                      "false_positive": False,
                                      "verifier_verdict": {}, "metrics": {},
                                      "narrative": "patched"})
    rc = cli.main(["run", "--target", "demo", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    assert rc == 0
    assert "ANTHROPIC_MODEL" not in capsys.readouterr().err


def test_model_not_found_hint_at_call_site(tmp_path, capsys):
    """A gateway 404ing the model name must be actionable, not a raw
    NotFoundError (this is the run that motivated the startup hint)."""
    import anthropic
    try:                              # anthropic>=1.13 in some envs vendors httpx2
        import httpx2 as httpx
    except ImportError:
        import httpx

    from jimmy.agent import Harness
    from jimmy.targets import LocalDemoTarget
    t = LocalDemoTarget(root=str(tmp_path / "jimmy-lab"))
    (tmp_path / "run").mkdir()
    h = Harness(t, str(tmp_path / "run"), client=object())

    def boom(**kw):
        resp = httpx.Response(404, request=httpx.Request("POST", "http://x"))
        raise anthropic.NotFoundError(
            "Error code: 404 - {'error': {'type': 'NotFoundError', "
            "'message': 'The model `claude-opus-5-5` does not exist.'}}",
            response=resp, body=None)

    h.client = types.SimpleNamespace(
        messages=types.SimpleNamespace(create=boom))
    with pytest.raises(anthropic.NotFoundError):
        h._call_api()
    err = capsys.readouterr().err
    assert "does not know model" in err and "ANTHROPIC_MODEL" in err


def test_api_error_plain_run_prints_one_clean_line(monkeypatch, tmp_path,
                                                   capsys):
    """Also guards the except clause itself: a mistyped SDK exception
    name only fails when the exception actually lands (APIRequestError
    vs APIStatusError bit exactly this way)."""
    import anthropic
    try:
        import httpx2 as httpx
    except ImportError:
        import httpx

    def boom(self):
        resp = httpx.Response(404, request=httpx.Request("POST", "http://x"))
        raise anthropic.NotFoundError(
            "Error code: 404 - The model does not exist.",
            response=resp, body=None)

    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key="sk-test",
                                                auth_token=None,
                                                credentials=None))
    monkeypatch.setattr(Harness, "run", boom)
    rc = cli.main(["run", "--target", "demo", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "API request failed: NotFoundError" in captured.err
    assert "Traceback" not in captured.err + captured.out


def test_run_with_credentials_proceeds(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key="sk-test",
                                                auth_token=None,
                                                credentials=None))
    monkeypatch.setattr(Harness, "run",
                        lambda self: {"status": "no_findings",
                                      "false_positive": False,
                                      "verifier_verdict": {}, "metrics": {},
                                      "narrative": "patched"})
    rc = cli.main(["run", "--target", "demo", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    assert rc == 0
    assert "no_findings" in capsys.readouterr().out


# ------------------------------------------------- --watch error surfacing

@pytest.mark.skipif(not TEXTUAL, reason="needs textual")
def test_watch_reports_thread_death_cleanly(monkeypatch, tmp_path, capsys):
    """A dying agent thread => one clear line + error.log, not a tangled
    cross-thread traceback."""
    from jimmy import tui

    class FakeApp:
        instances = []

        def __init__(self, run_dir, stop_fn=None, state=None,
                   attachable=False):
            self.state = state
            FakeApp.instances.append(self)

        def run(self):
            self.state["done"].wait(5)      # behave like a watcher

    def boom(self):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(tui, "WatchApp", FakeApp)
    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key="sk-test",
                                               auth_token=None, credentials=None))
    monkeypatch.setattr(Harness, "run", boom)
    rc = cli.main(["run", "--target", "demo", "--watch", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    err = capsys.readouterr().err
    assert rc == 1
    assert "agent died: RuntimeError: kaboom" in err
    assert "error.log" in err
    assert "Traceback" not in err          # the confusing part stays on disk
    log = (tmp_path / "r" / "error.log").read_text()
    assert "kaboom" in log and "Traceback" in log


@pytest.mark.skipif(not TEXTUAL, reason="needs textual")
def test_watch_prints_report_after_clean_run(monkeypatch, tmp_path, capsys):
    from jimmy import tui

    class FakeApp:
        def __init__(self, run_dir, stop_fn=None, state=None,
                   attachable=False):
            self.state = state

        def run(self):
            self.state["done"].wait(5)

    monkeypatch.setattr(tui, "WatchApp", FakeApp)
    monkeypatch.setattr("anthropic.Anthropic",
                        lambda **kw: FakeClient(api_key="sk-test",
                                               auth_token=None, credentials=None))
    monkeypatch.setattr(
        Harness, "run",
        lambda self: {"status": "success", "false_positive": False,
                      "verifier_verdict": {}, "metrics": {},
                      "narrative": "watched run"})
    rc = cli.main(["run", "--target", "demo", "--watch", "--yes",
                   "--run-dir", str(tmp_path / "r")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "watched run" in out
