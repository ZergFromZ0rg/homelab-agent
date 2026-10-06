"""The file browser. HOST_ROOT is emptied so a temp folder is both what the
agent reads and what a helper bind-mounts; the write tests use the real
Docker daemon when there is one."""

import io
import os
import sys
import tarfile
from unittest import mock

import pytest
from fastapi.testclient import TestClient

if "main" in sys.modules:
    import main
else:
    with mock.patch("docker.from_env", return_value=mock.MagicMock()):
        import main

import files
from disk_usage import DiskUsageError


@pytest.fixture(autouse=True)
def _host(monkeypatch, tmp_path):
    # Tests run as a normal user, so tmp_path would count as "owned by
    # someone other than root"; default to root-owned unless a test says so.
    monkeypatch.setattr(files, "_folder_uid", lambda path: 0)
    monkeypatch.setenv("HOST_ROOT", "")
    monkeypatch.setattr(files, "_roots_cache", None)
    monkeypatch.delenv("FILES_WRITABLE_PATHS", raising=False)
    monkeypatch.delenv("STACK_DIRS", raising=False)


def no_containers():
    client = mock.MagicMock()
    client.containers.list.return_value = []
    return client


def with_root(monkeypatch, root):
    monkeypatch.setenv("FILES_WRITABLE_PATHS", str(root))


def test_listing_marks_kinds_and_writability(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("hi")
    (tmp_path / "sub").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "a.txt")

    ro = files.listing(no_containers(), str(tmp_path), None)
    kinds = {e["name"]: e["kind"] for e in ro["entries"]}
    assert kinds == {"a.txt": "file", "sub": "dir", "link": "link"}
    assert ro["writable"] is False
    assert "root-owned" in ro["why_not"]

    with_root(monkeypatch, tmp_path)
    files._roots_cache = None
    assert files.listing(no_containers(), str(tmp_path / "sub"), None)["writable"] is True


def test_compose_folders_and_the_owners_home_are_roots(tmp_path, monkeypatch):
    passwd = tmp_path / "etc" / "passwd"
    passwd.parent.mkdir()
    passwd.write_text("root:x:0:0::/root:/bin/sh\nzerg:x:1000:1000::/home/zerg:/bin/bash\n")
    monkeypatch.setattr(files.disk_usage, "_on_host", lambda p: str(tmp_path) + p)

    client = mock.MagicMock()
    stack = mock.MagicMock()
    stack.labels = {"com.docker.compose.project.working_dir": "/srv/media"}
    client.containers.list.return_value = [stack]

    assert files.write_roots(client, 1000) == ["/home/zerg", "/srv/media"]


def test_a_non_root_owned_folder_is_changeable_without_being_a_root(tmp_path, monkeypatch):
    target = str(tmp_path / "media" / "clip.mp4")
    assert "FILES_WRITABLE_PATHS" in files.why_not_writable(target, [])
    monkeypatch.setattr(files, "_folder_uid", lambda path: 1000)
    assert files.why_not_writable(target, []) is None
    assert "operating system" in files.why_not_writable("/etc/passwd", [])
    assert "top-level" in files.why_not_writable("/mnt", [])


def test_the_os_and_the_root_are_never_roots(monkeypatch):
    monkeypatch.setenv("FILES_WRITABLE_PATHS", "/,/etc,/usr/local,/data")
    assert files.write_roots(no_containers(), None) == ["/data"]


def test_a_doubled_leading_slash_is_the_same_path(tmp_path, monkeypatch):
    with_root(monkeypatch, tmp_path)
    listed = files.listing(no_containers(), "/" + str(tmp_path), None)
    assert listed["path"] == str(tmp_path)
    assert listed["writable"] is True


def test_a_symlink_on_the_way_down_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "hop").symlink_to(real)
    reason = files.why_not_writable(str(tmp_path / "hop" / "x.txt"), [str(tmp_path)])
    assert "symlink" in reason


def test_read_text_refuses_binary_and_huge(tmp_path, monkeypatch):
    (tmp_path / "bin").write_bytes(b"\x00\x01")
    with pytest.raises(DiskUsageError, match="binary"):
        files.read_text(no_containers(), str(tmp_path / "bin"), None)

    monkeypatch.setattr(files, "TEXT_LIMIT", 4)
    (tmp_path / "big").write_text("12345")
    with pytest.raises(DiskUsageError, match="too big"):
        files.read_text(no_containers(), str(tmp_path / "big"), None)


def test_folder_archive_streams_a_real_tarball(tmp_path):
    (tmp_path / "d" / "e").mkdir(parents=True)
    (tmp_path / "d" / "one.txt").write_text("1")
    (tmp_path / "d" / "e" / "two.txt").write_text("22")

    chunks, name = files.folder_archive(str(tmp_path / "d"))
    data = b"".join(chunks)

    assert name == "d.tar.gz"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        assert sorted(tar.getnames()) == ["d", "d/e", "d/e/two.txt", "d/one.txt"]


def test_writes_outside_roots_are_refused_before_any_helper(tmp_path):
    client = no_containers()
    with pytest.raises(DiskUsageError, match="root-owned"):
        files.write_file(client, str(tmp_path / "x"), io.BytesIO(b"x"), 1, None, overwrite=False)
    client.containers.create.assert_not_called()


def test_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    monkeypatch.setattr(main, "_owner_uid", lambda: None)
    monkeypatch.setattr(main, "client", no_containers())
    (tmp_path / "f.txt").write_text("hello")
    web = TestClient(main.app)

    listed = web.get("/files/list", params={"path": str(tmp_path)}).json()
    assert [e["name"] for e in listed["entries"]] == ["f.txt"]

    text = web.get("/files/text", params={"path": str(tmp_path / "f.txt")}).json()
    assert text["content"] == "hello"

    got = web.get("/files/download", params={"path": str(tmp_path / "f.txt")})
    assert got.content == b"hello"
    assert "attachment" in got.headers["content-disposition"]

    assert web.get("/files/list", params={"path": "relative"}).status_code == 400
    refused = web.post("/files/mkdir", json={"path": str(tmp_path / "new")})
    assert refused.status_code == 400


# --- against a real daemon --------------------------------------------------

docker = pytest.importorskip("docker")
try:
    _real = docker.from_env()
    _real.ping()
    _DOCKER = True
except Exception:  # noqa: BLE001
    _DOCKER = False

needs_docker = pytest.mark.skipif(not _DOCKER, reason="no Docker daemon reachable")


@pytest.fixture
def writable(tmp_path, monkeypatch):
    # /private/var is what Docker Desktop shares; the /var symlink isn't.
    root = tmp_path.resolve()
    with_root(monkeypatch, root)
    monkeypatch.setattr(files.rebuild, "helper_image", lambda client: "alpine:3")
    return root


@needs_docker
def test_a_new_file_an_edit_and_a_stale_edit(writable):
    target = writable / "conf.yml"

    files.write_file(_real, str(target), io.BytesIO(b"a: 1\n"), 5, None, overwrite=False)
    assert target.read_text() == "a: 1\n"
    inode = target.stat().st_ino
    opened_at = target.stat().st_mtime

    with pytest.raises(files.Conflict, match="already exists"):
        files.write_file(_real, str(target), io.BytesIO(b"x"), 1, None, overwrite=False)

    files.write_file(
        _real, str(target), io.BytesIO(b"a: 2\n"), 5, None,
        overwrite=True, expected_modified=opened_at,
    )
    assert target.read_text() == "a: 2\n"
    # Same inode: a container bind-mounting this one file sees the edit.
    assert target.stat().st_ino == inode
    assert not [p for p in writable.iterdir() if p.name.startswith(".hl-")]

    with pytest.raises(files.Conflict, match="changed on disk"):
        files.write_file(
            _real, str(target), io.BytesIO(b"a: 3\n"), 5, None,
            overwrite=True, expected_modified=opened_at,
        )


@needs_docker
def test_rename_and_make_folder(writable):
    (writable / "old.txt").write_text("x")

    files.make_folder(_real, str(writable / "made"), None)
    assert (writable / "made").is_dir()

    files.rename(_real, str(writable / "old.txt"), "new.txt", None)
    assert (writable / "new.txt").read_text() == "x"
    assert not (writable / "old.txt").exists()

    with pytest.raises(files.Conflict):
        files.rename(_real, str(writable / "new.txt"), "made", None)
    with pytest.raises(DiskUsageError, match="root"):
        files.rename(_real, str(writable), "elsewhere", None)


@needs_docker
def test_upload_route_end_to_end(writable, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    monkeypatch.setattr(main, "_owner_uid", lambda: None)
    monkeypatch.setattr(main, "client", _real)
    payload = os.urandom(3 * 1024 * 1024 + 17)

    web = TestClient(main.app)
    resp = web.post("/files/upload", params={"path": str(writable / "blob.bin")}, content=payload)

    assert resp.status_code == 200, resp.text
    assert (writable / "blob.bin").read_bytes() == payload
    again = web.post("/files/upload", params={"path": str(writable / "blob.bin")}, content=b"x")
    assert again.status_code == 409


# --- move / copy / new file / delete, with the helper run in-process --------


class Helpers:
    """Stands in for the helper container: records the command and carries
    it out on the real temp folders (/target, /dest, /source are mapped)."""

    def __init__(self, monkeypatch):
        self.ran = []
        monkeypatch.setattr(files, "_owner", lambda p: (1000, 1000))
        monkeypatch.setattr(files, "_helper", self.make)
        monkeypatch.setattr(files, "_run", self.run)

    def make(self, client, folder, command, uid, gid, extra=None):
        mounts = {"/target": folder}
        for host, spec in (extra or {}).items():
            mounts[spec["bind"]] = host
        return {"command": command, "mounts": mounts, "extra": extra, "user": (uid, gid)}

    def run(self, helper):
        import shutil
        self.ran.append(helper)
        mounts, cmd = helper["mounts"], helper["command"]

        def real(arg):
            for bind, host in mounts.items():
                if arg == bind or arg.startswith(bind + "/"):
                    return host + arg[len(bind):]
            return os.path.join(mounts["/target"], arg)

        if cmd[0] == "mv":
            shutil.move(real(cmd[3]), real(cmd[4]))
        elif cmd[0] == "cp":
            src, dst = real(cmd[3]), real(cmd[4])
            (shutil.copytree if os.path.isdir(src) else shutil.copy2)(src, dst)


@pytest.fixture
def helpers(monkeypatch, tmp_path):
    with_root(monkeypatch, tmp_path)
    return Helpers(monkeypatch)


def test_move_to_another_folder(helpers, tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "f.txt").write_text("x")

    out = files.move(no_containers(), str(tmp_path / "a" / "f.txt"), str(tmp_path / "b" / "g.txt"), None)

    assert out["path"] == str(tmp_path / "b" / "g.txt")
    assert (tmp_path / "b" / "g.txt").read_text() == "x"
    assert not (tmp_path / "a" / "f.txt").exists()
    # Source folder is writable and runs the move; destination is beside it.
    assert helpers.ran[0]["mounts"]["/target"] == str(tmp_path / "a")


def test_move_refuses_into_itself_onto_existing_and_roots(helpers, tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "e.txt").write_text("1")
    (tmp_path / "f.txt").write_text("2")
    client = no_containers()

    with pytest.raises(DiskUsageError, match="into itself"):
        files.move(client, str(tmp_path / "d"), str(tmp_path / "d" / "sub"), None)
    with pytest.raises(files.Conflict, match="already exists"):
        files.move(client, str(tmp_path / "e.txt"), str(tmp_path / "f.txt"), None)
    with pytest.raises(DiskUsageError, match="is a root"):
        files.move(client, str(tmp_path), str(tmp_path.parent / "other"), None)
    assert helpers.ran == []


def test_move_refuses_a_folder_a_container_is_using(helpers, tmp_path):
    (tmp_path / "data").mkdir()
    client = no_containers()
    running = mock.MagicMock()
    running.name = "jellyfin"
    running.attrs = {"Mounts": [{"Type": "bind", "Source": str(tmp_path / "data")}]}
    client.containers.list.return_value = [running]

    with pytest.raises(DiskUsageError, match="jellyfin is using"):
        files.move(client, str(tmp_path / "data"), str(tmp_path / "data2"), None)
    assert helpers.ran == []


def test_copy_reads_from_anywhere_and_writes_where_allowed(helpers, tmp_path, monkeypatch):
    src = tmp_path / "ro"
    src.mkdir()
    (src / "n.txt").write_text("n")
    dest = tmp_path / "w"
    dest.mkdir()

    out = files.copy(no_containers(), str(src / "n.txt"), str(dest / "n copy.txt"), None)

    assert (dest / "n copy.txt").read_text() == "n"
    assert (src / "n.txt").exists()
    assert out["path"] == str(dest / "n copy.txt")
    assert helpers.ran[0]["extra"][str(src)]["mode"] == "ro"

    with pytest.raises(DiskUsageError, match="root-owned"):
        files.copy(no_containers(), str(src / "n.txt"), "/srv/elsewhere/n.txt", None)
    with pytest.raises(files.Conflict):
        files.copy(no_containers(), str(src / "n.txt"), str(dest / "n copy.txt"), None)


def test_new_file_is_an_empty_write(helpers, tmp_path, monkeypatch):
    seen = {}

    def fake_write(client, path, source, size, uid, *, overwrite, expected_modified=None):
        seen.update(path=path, size=size, data=source.read(), overwrite=overwrite)
        return {"success": True}

    monkeypatch.setattr(files, "write_file", fake_write)
    files.new_file(no_containers(), str(tmp_path / "x.txt"), None)
    assert seen == {"path": str(tmp_path / "x.txt"), "size": 0, "data": b"", "overwrite": False}


def test_delete_follows_the_same_rule_as_writes(tmp_path, monkeypatch):
    client = no_containers()
    (tmp_path / "f").write_text("x")
    # Root-owned and outside every root: refused before disk_delete runs.
    monkeypatch.setattr(files.disk_delete, "delete", mock.Mock(side_effect=AssertionError))
    with pytest.raises(DiskUsageError, match="root-owned"):
        files.delete(client, str(tmp_path / "f"), None)

    with_root(monkeypatch, tmp_path)
    files._roots_cache = None
    monkeypatch.setattr(files.disk_delete, "delete", lambda c, p: {"success": True, "path": p})
    assert files.delete(client, str(tmp_path / "f"), None)["success"]
    with pytest.raises(DiskUsageError, match="is a root"):
        files.delete(client, str(tmp_path), None)


def test_new_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "AGENT_TOKEN", "")
    monkeypatch.setattr(main, "_owner_uid", lambda: None)
    monkeypatch.setattr(main, "client", no_containers())
    web = TestClient(main.app)
    for route, body in (
        ("newfile", {"path": str(tmp_path / "n")}),
        ("move", {"path": str(tmp_path / "a"), "dest": str(tmp_path / "b")}),
        ("copy", {"path": str(tmp_path / "a"), "dest": str(tmp_path / "b")}),
        ("delete", {"path": str(tmp_path / "a")}),
    ):
        assert web.post(f"/files/{route}", json=body).status_code == 400  # refused by policy
