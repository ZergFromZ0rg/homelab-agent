"""Version reporting: what's running, what's on disk, what's on the remote."""

import subprocess
from unittest import mock

import pytest

import version


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("VERSION_CACHE", raising=False)
    version.reset_cache()
    yield
    version.reset_cache()


def a_repo(tmp_path, commits=1):
    """A real git checkout — the parsing here is against git's actual
    output, so faking it would test nothing."""
    repo = tmp_path / "agent"
    repo.mkdir()
    run = lambda *a: subprocess.run(  # noqa: E731
        ["git", *a], cwd=repo, capture_output=True, check=True
    )
    run("init", "-q", "-b", "main")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    for i in range(commits):
        (repo / "f").write_text(str(i))
        run("add", "f")
        run("commit", "-qm", f"c{i}")
    return repo


def head_sha(repo):
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()


# ---- reading the checkout -------------------------------------------------


def test_source_info_reads_head(tmp_path):
    repo = a_repo(tmp_path)

    info = version.source_info(str(repo))

    assert info["sha"] == head_sha(repo)
    assert info["short"] == info["sha"][:7]
    assert info["branch"] == "main"
    assert isinstance(info["committed_at"], float)


def test_a_directory_that_is_not_a_checkout(tmp_path):
    (tmp_path / "plain").mkdir()
    assert version.source_info(str(tmp_path / "plain")) is None


def test_a_path_that_does_not_exist():
    assert version.source_info("/definitely/not/here") is None


# ---- image build time -----------------------------------------------------


def client_with_image(created):
    client = mock.MagicMock()
    container = mock.MagicMock()
    container.image.attrs = {"Created": created}
    client.containers.get.return_value = container
    return client


def test_image_created_parses_dockers_nanosecond_timestamps():
    """Docker reports more precision than fromisoformat takes on some
    versions."""
    client = client_with_image("2026-09-21T20:27:51.775288778Z")

    ts = version.image_created(client, "abc")

    assert ts is not None and 1790000000 < ts < 1800000000


def test_image_created_handles_a_plain_timestamp():
    assert version.image_created(client_with_image("2026-09-21T20:27:51Z"), "abc")


def test_image_created_survives_a_broken_client():
    client = mock.MagicMock()
    client.containers.get.side_effect = RuntimeError("daemon gone")
    assert version.image_created(client, "abc") is None


def test_image_created_handles_a_missing_field():
    assert version.image_created(client_with_image(None), "abc") is None


# ---- the report -----------------------------------------------------------


def report(repo, image_created_at, monkeypatch, remote=None):
    monkeypatch.setattr(version, "image_created", lambda *a: image_created_at)
    monkeypatch.setattr(version, "remote_sha", lambda *a: remote)
    return version.report(mock.MagicMock(), str(repo))


def test_a_pull_without_a_rebuild_is_flagged(tmp_path, monkeypatch):
    """The state we kept hitting by hand: the checkout carries a commit
    the running image cannot contain."""
    repo = a_repo(tmp_path)
    committed = version.source_info(str(repo))["committed_at"]

    out = report(repo, committed - 60, monkeypatch)   # image built before it

    assert out["needs_rebuild"] is True


def test_an_image_built_after_the_commit_is_current(tmp_path, monkeypatch):
    repo = a_repo(tmp_path)
    committed = version.source_info(str(repo))["committed_at"]

    out = report(repo, committed + 60, monkeypatch)

    assert out["needs_rebuild"] is False


def test_build_time_is_compared_not_a_baked_sha(tmp_path, monkeypatch):
    """Comparing a sha baked in at build time would go wrong the moment a
    container is restarted without being rebuilt. The build timestamp
    doesn't."""
    repo = a_repo(tmp_path)
    committed = version.source_info(str(repo))["committed_at"]

    # Restarted long after the build, checkout untouched: still current.
    assert report(repo, committed + 5, monkeypatch)["needs_rebuild"] is False


def test_being_behind_the_remote_is_separate_from_needing_a_rebuild(tmp_path, monkeypatch):
    repo = a_repo(tmp_path)
    committed = version.source_info(str(repo))["committed_at"]

    out = report(repo, committed + 60, monkeypatch, remote="f" * 40)

    assert out["behind_remote"] is True      # remote has something newer
    assert out["needs_rebuild"] is False     # but disk matches the image


def test_matching_the_remote_is_not_behind(tmp_path, monkeypatch):
    repo = a_repo(tmp_path)
    sha = head_sha(repo)

    out = report(repo, 9e9, monkeypatch, remote=sha)

    assert out["behind_remote"] is False
    assert out["remote_sha"] == sha


def test_no_remote_reachable_is_not_reported_as_behind(tmp_path, monkeypatch):
    """No network is not the same as being out of date."""
    repo = a_repo(tmp_path)

    out = report(repo, 9e9, monkeypatch, remote=None)

    assert out["remote_sha"] is None and out["behind_remote"] is False


def test_an_agent_with_no_checkout_reports_nothing_rather_than_failing():
    out = version.report(mock.MagicMock(), None)

    assert out["source"] is None
    assert out["needs_rebuild"] is False and out["behind_remote"] is False


def test_the_remote_check_is_cached(tmp_path, monkeypatch):
    repo = a_repo(tmp_path)
    calls = []

    monkeypatch.setattr(version, "image_created", lambda *a: 9e9)
    monkeypatch.setattr(
        version, "remote_sha", lambda *a: calls.append(1) or "a" * 40
    )

    version.report(mock.MagicMock(), str(repo))
    version.report(mock.MagicMock(), str(repo))

    assert len(calls) == 1, "ls-remote is the only network call here"

    version.reset_cache()
    version.report(mock.MagicMock(), str(repo))
    assert len(calls) == 2
