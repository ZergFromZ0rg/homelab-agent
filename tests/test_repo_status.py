"""Whether a project's checkout is behind GitHub. Real git against throwaway
repositories (a local path stands in for GitHub's URL); no network."""

import subprocess
import time

import pytest

import repo_status


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True,
    )


@pytest.fixture
def repos(tmp_path):
    """A bare 'remote' and a clone of it with one commit pushed."""
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    git(tmp_path, "clone", str(remote), str(work))
    (work / "a.txt").write_text("one\n")
    git(work, "add", ".")
    git(work, "commit", "-m", "first")
    git(work, "push", "origin", "HEAD:main")
    return remote, work


def push_from_elsewhere(tmp_path, remote, name="two"):
    other = tmp_path / f"other-{name}"
    git(tmp_path, "clone", str(remote), str(other))
    (other / f"{name}.txt").write_text(name)
    git(other, "add", ".")
    git(other, "commit", "-m", f"add {name}")
    git(other, "push", "origin", "HEAD:main")


def state_of(work, remote):
    info = repo_status.local_info(str(work))
    tip, why = repo_status.remote_tip(str(remote), info["branch"], str(work))
    assert why is None, why
    return repo_status.compare(str(work), info["sha"], tip)


class TestGithubRepo:
    @pytest.mark.parametrize("url", [
        "https://github.com/ZergFromZ0rg/ai-librarian.git",
        "git@github.com:ZergFromZ0rg/ai-librarian.git",
        "ssh://git@github.com/ZergFromZ0rg/ai-librarian",
        "https://github.com/ZergFromZ0rg/ai-librarian/",
    ])
    def test_reads_owner_and_name_however_the_remote_is_written(self, url):
        assert repo_status.github_repo(url) == ("ZergFromZ0rg", "ai-librarian")

    @pytest.mark.parametrize("url", [None, "", "/srv/repos/thing.git", "https://gitlab.com/a/b.git"])
    def test_says_nothing_for_a_remote_that_is_not_github(self, url):
        assert repo_status.github_repo(url) is None


class TestLocalInfo:
    def test_reads_branch_commit_and_subject(self, repos):
        _, work = repos
        info = repo_status.local_info(str(work))
        assert info["branch"] == "main"
        assert info["subject"] == "first"
        assert len(info["sha"]) == 40 and info["short"] == info["sha"][:7]
        assert info["dirty"] is False

    def test_a_modified_tracked_file_is_dirty(self, repos):
        _, work = repos
        (work / "a.txt").write_text("changed\n")
        assert repo_status.local_info(str(work))["dirty"] is True

    def test_an_untracked_file_is_not(self, repos):
        _, work = repos
        (work / "new.txt").write_text("x")
        assert repo_status.local_info(str(work))["dirty"] is False

    def test_a_detached_head_has_no_branch(self, repos):
        _, work = repos
        git(work, "checkout", "-q", "--detach")
        assert repo_status.local_info(str(work))["branch"] is None

    def test_not_a_checkout_is_none(self, tmp_path):
        assert repo_status.local_info(str(tmp_path)) is None

    def test_reading_never_writes_to_the_checkout(self, repos):
        _, work = repos
        before = sorted((p.name, p.stat().st_mtime_ns) for p in (work / ".git").iterdir() if p.is_file())
        repo_status.local_info(str(work))
        after = sorted((p.name, p.stat().st_mtime_ns) for p in (work / ".git").iterdir() if p.is_file())
        assert before == after


class TestCompare:
    def test_up_to_date(self, repos):
        remote, work = repos
        assert state_of(work, remote) == "up_to_date"

    def test_behind_when_someone_pushed(self, repos, tmp_path):
        remote, work = repos
        push_from_elsewhere(tmp_path, remote)
        assert state_of(work, remote) == "behind"

    def test_ahead_when_the_checkout_has_unpushed_commits(self, repos):
        remote, work = repos
        (work / "b.txt").write_text("b")
        git(work, "add", ".")
        git(work, "commit", "-m", "local only")
        assert state_of(work, remote) == "ahead"

    def test_a_remote_that_cannot_be_read_says_why_instead_of_guessing(self, repos, tmp_path):
        _, work = repos
        tip, why = repo_status.remote_tip(str(tmp_path / "nowhere.git"), "main", str(work))
        assert tip is None and why

    def test_a_branch_the_remote_lacks_is_named(self, repos):
        remote, work = repos
        tip, why = repo_status.remote_tip(str(remote), "no-such-branch", str(work))
        assert tip is None and "no-such-branch" in why


class TestTracking:
    def target(self, work, remote_url):
        return {"path": str(work), "remote": remote_url, "fetch_url": remote_url}

    @pytest.fixture(autouse=True)
    def _clean(self):
        for d in (repo_status._tracked, repo_status._state, repo_status._remotes):
            d.clear()
        yield
        for d in (repo_status._tracked, repo_status._state, repo_status._remotes):
            d.clear()

    def test_nothing_is_said_about_a_project_without_a_github_checkout(self, repos):
        _, work = repos
        assert repo_status.lookup(None) is None
        assert repo_status.lookup(self.target(work, "https://gitlab.com/a/b.git")) is None

    def test_first_sight_is_checking_then_the_pass_answers(self, repos, monkeypatch):
        remote, work = repos
        url = "https://github.com/me/thing.git"
        first = repo_status.lookup(self.target(work, url))
        assert first["state"] == "checking" and (first["owner"], first["name"]) == ("me", "thing")

        # The pass reads the real checkout; GitHub is a local bare repo.
        real = repo_status.remote_tip
        monkeypatch.setattr(repo_status, "remote_tip", lambda u, b, c: real(str(remote), b, c))
        repo_status.run_once()
        answered = repo_status.lookup(self.target(work, url))
        assert answered["state"] == "up_to_date"
        assert answered["branch"] == "main" and answered["dirty"] is False

    def test_a_push_shows_as_behind_after_the_remote_is_asked_again(self, repos, tmp_path, monkeypatch):
        remote, work = repos
        url = "https://github.com/me/thing.git"
        real = repo_status.remote_tip
        monkeypatch.setattr(repo_status, "remote_tip", lambda u, b, c: real(str(remote), b, c))
        repo_status.lookup(self.target(work, url))
        repo_status.run_once()
        assert repo_status.lookup(self.target(work, url))["state"] == "up_to_date"

        push_from_elsewhere(tmp_path, remote)
        repo_status.invalidate(str(work))
        repo_status.run_once()
        seen = repo_status.lookup(self.target(work, url))
        assert seen["state"] == "behind"
        assert seen["remote_short"] and seen["remote_short"] != seen["short"]

    def test_an_unreadable_remote_is_unknown_with_a_reason(self, repos, monkeypatch):
        _, work = repos
        monkeypatch.setattr(repo_status, "remote_tip", lambda *a: (None, "private repo — the agent has no GitHub credentials"))
        url = "https://github.com/me/thing.git"
        repo_status.lookup(self.target(work, url))
        repo_status.run_once()
        seen = repo_status.lookup(self.target(work, url))
        assert seen["state"] == "unknown" and "private" in seen["error"]

    def test_a_checkout_nobody_asks_about_is_forgotten(self, repos):
        _, work = repos
        repo_status.lookup(self.target(work, "https://github.com/me/thing.git"))
        repo_status.run_once(time.time() + repo_status.FORGET_AFTER + 5)
        assert str(work) not in repo_status._tracked
