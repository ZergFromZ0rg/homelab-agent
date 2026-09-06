import yaml
import pytest

import deploy
import stack_deploy
from stack_deploy import CreateStackRequest, PolicyError, check_stack_policy


def doc(text):
    return yaml.safe_load(text)


def policy(text, name="s"):
    check_stack_policy(doc(text), name)


# ---- name validation ------------------------------------------------


def test_name_validation():
    with pytest.raises(ValueError):
        CreateStackRequest(name="Bad Name", compose_yaml="services: {}")
    with pytest.raises(ValueError):
        CreateStackRequest(name="../evil", compose_yaml="x")
    assert CreateStackRequest(name="Media_Stack", compose_yaml="x").name == "media_stack"


def test_remove_stack_rejects_traversal_names():
    for bad in ("..", "../../etc", ".%2e", "foo/bar"):
        with pytest.raises(PolicyError):
            stack_deploy.remove_stack(object(), bad)


# ---- service-key allowlist ----------------------------------------


def test_unknown_service_key_rejected():
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    privileged: true\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    cap_add: [SYS_ADMIN]\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    userns_mode: host\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    volumes_from: [other]\n")


def test_common_keys_allowed():
    policy(
        """
services:
  web:
    image: nginx
    ports: ["8080:80"]
    environment: {TZ: UTC}
    volumes: [data:/data]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits: {memory: 256M}
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
volumes:
  data:
"""
    )


def test_build_rejected():
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    build: .\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    build: {}\n")


# ---- namespace / isolation ---------------------------------------


def test_host_namespace_rejected():
    for line in (
        "network_mode: host",
        "network_mode: 'container:homelab-agent'",
        "network_mode: 'service:other'",
        "pid: host",
        "pid: 'container:homelab-agent'",
        "ipc: host",
        "ipc: 'container:x'",
    ):
        with pytest.raises(PolicyError):
            policy(f"services:\n  a:\n    image: x\n    {line}\n")


def test_unsafe_security_opt_rejected():
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    security_opt: ['seccomp:unconfined']\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    security_opt: ['apparmor:unconfined']\n")


# ---- the named-volume-that-is-a-bind bypass ---------------------


def test_bind_disguised_as_named_volume_rejected(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", [])
    compose = """
services:
  a:
    image: x
    volumes:
      - sneaky:/host
volumes:
  sneaky:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /
"""
    with pytest.raises(PolicyError):
        policy(compose)


def test_bind_named_volume_allowed_when_device_is_allowlisted(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", ["/srv/media"])
    policy(
        """
services:
  a:
    image: x
    volumes: [media:/media]
volumes:
  media:
    driver_opts: {type: none, o: bind, device: /srv/media/movies}
"""
    )


# ---- devices ---------------------------------------------------


def test_devices_need_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_DEVICES", [])
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    devices: ['/dev/dri:/dev/dri']\n")

    monkeypatch.setattr(deploy, "ALLOWED_DEVICES", ["/dev/dri"])
    policy("services:\n  a:\n    image: x\n    devices: ['/dev/dri/renderD128:/dev/dri/renderD128']\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    devices: ['/dev/sda:/dev/sda']\n")


# ---- registry / bind volume / labels --------------------------


def test_registry_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_REGISTRIES", ["docker.io"])
    policy("services:\n  a:\n    image: nginx\n")
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: ghcr.io/x/y\n")


def test_service_bind_mount_needs_allowlist(monkeypatch):
    monkeypatch.setattr(deploy, "ALLOWED_HOST_PATHS", [])
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n    volumes: ['/etc:/host-etc']\n")


def test_reserved_service_label_rejected():
    with pytest.raises(PolicyError):
        policy(
            "services:\n  a:\n    image: x\n    labels:\n      com.docker.compose.project: fake\n"
        )


def test_stray_top_level_key_rejected():
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\nsecrets:\n  s:\n    file: /etc/shadow\n")


def test_protected_project_name():
    with pytest.raises(PolicyError):
        policy("services:\n  a:\n    image: x\n", name="homelab-agent")


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
