"""Tests for ``tutorial_02/sqlmap_runner.py``.

Pure-function tests — we don't invoke sqlmap. The runner is dumb by
design (subprocess wrapper only), so what's worth testing is just the
argv construction.
"""
from __future__ import annotations

import pytest

from tutorial_02.sqlmap_runner import (
    SqlmapMissingError,
    build_sqlmap_command,
)


def test_build_sqlmap_command_includes_always_on_flags(monkeypatch):
    """Every sqlmap run must be non-interactive and dump data."""
    # Fake the sqlmap binary lookup so the test passes regardless of
    # whether sqlmap is on PATH.
    monkeypatch.setattr(
        "tutorial_02.sqlmap_runner._require_sqlmap",
        lambda: "/fake/sqlmap",
    )
    cmd = build_sqlmap_command(
        url="http://localhost:8080/WebGoat/SqlInjection/assignment5b",
    )
    assert cmd[0] == "/fake/sqlmap"
    assert "--batch" in cmd
    assert "--dump" in cmd
    # -u <url> appears as adjacent argv pairs.
    u_idx = cmd.index("-u")
    assert cmd[u_idx + 1].endswith("/assignment5b")
    # --dbms defaults to hsqldb.
    dbms_idx = cmd.index("--dbms")
    assert cmd[dbms_idx + 1] == "hsqldb"


def test_build_sqlmap_command_omits_p_flag_when_no_parameter_given(monkeypatch):
    """When ``parameter`` is None the wrapper must NOT add ``-p`` —
    omitting it tells sqlmap to test every parameter in --data
    (the right default for black-box discovery)."""
    monkeypatch.setattr(
        "tutorial_02.sqlmap_runner._require_sqlmap",
        lambda: "/fake/sqlmap",
    )
    cmd = build_sqlmap_command(
        url="http://localhost:8080/WebGoat/SqlInjection/assignment5b",
        data="login_count=1&userid=1",
    )
    assert "-p" not in cmd


def test_build_sqlmap_command_adds_p_flag_when_parameter_given(monkeypatch):
    """``parameter='login_count'`` should land as ``-p login_count``."""
    monkeypatch.setattr(
        "tutorial_02.sqlmap_runner._require_sqlmap",
        lambda: "/fake/sqlmap",
    )
    cmd = build_sqlmap_command(
        url="http://localhost:8080/WebGoat/SqlInjection/assignment5b",
        parameter="login_count",
    )
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "login_count"


def test_build_sqlmap_command_threads_optional_flags(monkeypatch):
    monkeypatch.setattr(
        "tutorial_02.sqlmap_runner._require_sqlmap",
        lambda: "/fake/sqlmap",
    )
    cmd = build_sqlmap_command(
        url="http://localhost:8080/WebGoat/SqlInjection/assignment5b",
        data="login_count=1&userid=1",
        cookie="JSESSIONID=ABC123",
        dbms="mysql",
        extra_args=["--level=3"],
    )
    assert "--data" in cmd
    assert cmd[cmd.index("--data") + 1] == "login_count=1&userid=1"
    assert "--cookie" in cmd
    assert cmd[cmd.index("--cookie") + 1] == "JSESSIONID=ABC123"
    assert cmd[cmd.index("--dbms") + 1] == "mysql"
    assert "--level=3" in cmd


def test_build_sqlmap_command_does_not_add_content_type_header(monkeypatch):
    """The wrapper deliberately does NOT auto-set Content-Type. sqlmap's
    own default (application/x-www-form-urlencoded for --data) matches
    WebGoat's SQLi lesson endpoints. For JSON-body targets the caller
    must pass ``-H`` themselves via ``extra_args``; auto-guessing the
    Content-Type from body shape leads to silent 400-on-every-request
    failures when the guess is wrong."""
    monkeypatch.setattr(
        "tutorial_02.sqlmap_runner._require_sqlmap",
        lambda: "/fake/sqlmap",
    )
    cmd = build_sqlmap_command(
        url="http://localhost:8080/WebGoat/SqlInjection/assignment5b",
        data="login_count=1&userid=1",
    )
    assert "-H" not in cmd
    assert "--header" not in cmd
    assert "--headers" not in cmd


def test_build_sqlmap_command_omits_optional_flags_when_not_provided(monkeypatch):
    monkeypatch.setattr(
        "tutorial_02.sqlmap_runner._require_sqlmap",
        lambda: "/fake/sqlmap",
    )
    cmd = build_sqlmap_command(
        url="http://localhost/x",
    )
    assert "--data" not in cmd
    assert "--cookie" not in cmd
    assert "-p" not in cmd


def test_require_sqlmap_raises_clear_error_when_missing(monkeypatch):
    """Missing sqlmap binary → friendly error pointing at install path."""
    monkeypatch.setattr("shutil.which", lambda x: None)
    from tutorial_02.sqlmap_runner import _require_sqlmap
    with pytest.raises(SqlmapMissingError, match="sqlmap"):
        _require_sqlmap()
