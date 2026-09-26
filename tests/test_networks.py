import docker
import pytest

import networks
from networks import NetworkError


class FakeNetwork:
    def __init__(self, name, containers=None, subnet="172.20.0.0/16", driver="bridge"):
        self.name = name
        self.id = f"{name}-id-0000000000"
        self.removed = False
        self.connected = []
        self.disconnected = []
        self.attrs = {
            "Id": self.id,
            "Name": name,
            "Driver": driver,
            "Scope": "local",
            "Internal": False,
            "Attachable": True,
            "IPAM": {"Config": [{"Subnet": subnet, "Gateway": "172.20.0.1"}]},
            "Labels": {"com.docker.compose.project": "media"},
            "Containers": {
                f"{c}-cid-000000000": {
                    "Name": c,
                    "IPv4Address": "172.20.0.5/16",
                    "MacAddress": "02:42:ac:14:00:05",
                }
                for c in (containers or [])
            },
        }

    def reload(self):
        pass

    def remove(self):
        self.removed = True

    def connect(self, container):
        self.connected.append(container.name)

    def disconnect(self, container):
        self.disconnected.append(container.name)


class FakeContainer:
    def __init__(self, name):
        self.name = name


class FakeClient:
    def __init__(self, nets, containers=("jellyfin", "homelab-agent")):
        self._nets = {n.name: n for n in nets}
        self._containers = set(containers)
        self.created = []
        outer = self

        class Networks:
            def list(self, greedy=False):
                return list(outer._nets.values())

            def get(self, key):
                for n in outer._nets.values():
                    if key in (n.name, n.id, n.id[:12]):
                        return n
                raise docker.errors.NotFound(key)

            def create(self, name, **kwargs):
                if name in outer._nets:
                    raise docker.errors.APIError("exists", explanation=f"network with name {name} already exists")
                outer.created.append((name, kwargs))
                net = FakeNetwork(name)
                outer._nets[name] = net
                return net

        class Containers:
            def get(self, name):
                if name in outer._containers:
                    return FakeContainer(name)
                raise docker.errors.NotFound(name)

        self.networks = Networks()
        self.containers = Containers()


PROTECTED = {"homelab-agent"}


def test_lists_members_and_puts_builtins_last():
    client = FakeClient([FakeNetwork("bridge"), FakeNetwork("media", ["jellyfin"])])
    rows = networks.list_networks(client)

    assert [r["name"] for r in rows] == ["media", "bridge"]
    media = rows[0]
    assert media["subnets"] == ["172.20.0.0/16"]
    assert media["containers"][0] == {
        "id": "jellyfin-cid",
        "name": "jellyfin",
        "ipv4": "172.20.0.5",
        "ipv6": None,
        "mac": "02:42:ac:14:00:05",
    }
    assert rows[1]["builtin"] is True


def test_create_validates_name_and_subnet():
    client = FakeClient([])
    with pytest.raises(NetworkError):
        networks.create_network(client, "bad name!")
    with pytest.raises(NetworkError):
        networks.create_network(client, "host")
    with pytest.raises(NetworkError):
        networks.create_network(client, "lan", subnet="10.0.0.1/24")  # host bits set

    row = networks.create_network(client, "lan", subnet="10.9.0.0/24", internal=True)
    assert row["name"] == "lan"
    name, kwargs = client.created[0]
    assert kwargs["driver"] == "bridge" and kwargs["internal"] is True


def test_create_reports_dockers_reason():
    client = FakeClient([FakeNetwork("lan")])
    with pytest.raises(NetworkError, match="already exists"):
        networks.create_network(client, "lan")


def test_remove_refuses_builtin_and_in_use():
    busy = FakeNetwork("media", ["jellyfin"])
    client = FakeClient([FakeNetwork("bridge"), busy, FakeNetwork("empty")])

    with pytest.raises(NetworkError, match="Docker's own"):
        networks.remove_network(client, "bridge")
    with pytest.raises(NetworkError, match="jellyfin"):
        networks.remove_network(client, "media")

    assert networks.remove_network(client, "empty") == "empty"
    assert client._nets["empty"].removed


def test_connect_and_disconnect_skip_protected():
    net = FakeNetwork("media")
    client = FakeClient([net, FakeNetwork("host")])

    with pytest.raises(NetworkError, match="protected"):
        networks.connect(client, "media", "homelab-agent", PROTECTED)
    with pytest.raises(NetworkError, match="protected"):
        networks.disconnect(client, "media", "homelab-agent", PROTECTED)
    with pytest.raises(NetworkError, match="no container"):
        networks.connect(client, "media", "ghost", PROTECTED)
    with pytest.raises(NetworkError, match="created"):
        networks.connect(client, "host", "jellyfin", PROTECTED)

    assert networks.connect(client, "media", "jellyfin", PROTECTED) == {
        "network": "media",
        "container": "jellyfin",
    }
    networks.disconnect(client, "media", "jellyfin", PROTECTED)
    assert net.connected == ["jellyfin"] and net.disconnected == ["jellyfin"]


def test_unknown_network():
    with pytest.raises(NetworkError, match="no network"):
        networks.remove_network(FakeClient([]), "nope")
