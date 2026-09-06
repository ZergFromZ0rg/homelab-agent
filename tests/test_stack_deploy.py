import yaml
import pytest

import deploy
import stack_deploy
from stack_deploy import CreateStackRequest, PolicyError, check_stack_policy


def doc(text):
    return yaml.safe_load(text)


def test_name_validation():
    with pytest.raises(ValueError):
        CreateStackRequest(name="Bad Name", compose_yaml="services: {}")
    assert CreateStackRequest(name="Media_Stack", compose_yaml="x").name == "media_stack"


def test_build_rejected():
    d = doc("services:\n  app:\n    build: .\n")
    with pytest.raises(PolicyError):
        check_stack_policy(d, "s")


def test_privileged_rejected():
    d = doc("services:\n  app:\n    image: x\n    privileged: true\n")
    with pytest.raises(PolicyError):
        check_stack_policy(d, "s")


def test_host_network_rejected():
    d = doc("services:\n  app:\n    image: x\n    network_mode: host\n")
    with pytest.raises(PolicyError):
        check_stack_policy(d, "s")


def test_registry_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_REGISTRIES", ["docker.io"])
    check_stack_policy(doc("services:\n  a:\n    image: nginx\n"), "s")
    with pytest.raises(PolicyError):
        check_stack_policy(doc("services:\n  a:\n    image: ghcr.io/x/y\n"), "s")


def test_bind_mount_needs_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", [])
    d = doc("services:\n  a:\n    image: x\n    volumes:\n      - /etc:/host-etc\n")
    with pytest.raises(PolicyError):
        check_stack_policy(d, "s")

    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", ["/srv/appdata"])
    ok = doc("services:\n  a:\n    image: x\n    volumes:\n      - /srv/appdata/a:/data\n")
    check_stack_policy(ok, "s")


def test_named_volume_ok(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", [])
    d = doc("services:\n  a:\n    image: x\n    volumes:\n      - data:/data\n")
    check_stack_policy(d, "s")


def test_protected_project_name():
    with pytest.raises(PolicyError):
        check_stack_policy(doc("services:\n  a:\n    image: x\n"), "homelab-agent")


def test_deploy_stack_rejects_before_running_compose(monkeypatch, tmp_path):
    monkeypatch.setattr(stack_deploy, "STACK_DIR", tmp_path)
    called = []
    monkeypatch.setattr(stack_deploy, "_compose", lambda *a, **k: called.append(a))

    req = CreateStackRequest(
        name="s", compose_yaml="services:\n  a:\n    image: x\n    privileged: true\n"
    )
    with pytest.raises(PolicyError):
        stack_deploy.deploy_stack(object(), req)
    assert called == []
