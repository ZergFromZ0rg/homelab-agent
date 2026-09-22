import pytest

import connections


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("CONNECTIONS_ENABLED", raising=False)
    monkeypatch.delenv("CONNECTIONS_MAX_PEERS", raising=False)
    monkeypatch.delenv("CONNECTIONS_CACHE", raising=False)
    monkeypatch.delenv("CONNTRACK_FILE", raising=False)
    connections.reset_cache()
    yield
    connections.reset_cache()


# Real-shaped rows. An accounted TCP flow, a UDP flow (no state field), an
# unanswered flow (no reply counters), ICMP (type/code/id, no ports), IPv6,
# and a row from a kernel with accounting switched off.
ACCOUNTED_TCP = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 "
    "sport=51234 dport=443 packets=12 bytes=1440 src=1.1.1.1 dst=10.0.0.5 "
    "sport=443 dport=51234 packets=10 bytes=5000 [ASSURED] mark=0 use=1"
)
UDP = (
    "ipv4     2 udp      17 29 src=10.0.0.5 dst=8.8.8.8 sport=41234 dport=53 "
    "packets=1 bytes=64 src=8.8.8.8 dst=10.0.0.5 sport=53 dport=41234 "
    "packets=1 bytes=160 mark=0 use=1"
)
UNREPLIED = (
    "ipv4     2 tcp      6 118 SYN_SENT src=10.0.0.5 dst=192.0.2.9 "
    "sport=50000 dport=8080 packets=3 bytes=180 [UNREPLIED] "
    "src=192.0.2.9 dst=10.0.0.5 sport=8080 dport=50000 packets=0 bytes=0 "
    "mark=0 use=1"
)
ICMP = (
    "ipv4     2 icmp     1 29 src=10.0.0.5 dst=1.1.1.1 type=8 code=0 id=1234 "
    "packets=1 bytes=84 src=1.1.1.1 dst=10.0.0.5 type=0 code=0 id=1234 "
    "packets=1 bytes=84 mark=0 use=1"
)
IPV6 = (
    "ipv6     10 tcp      6 431999 ESTABLISHED src=fd00::1 dst=fd00::2 "
    "sport=40000 dport=22 packets=5 bytes=400 src=fd00::2 dst=fd00::1 "
    "sport=22 dport=40000 packets=5 bytes=600 [ASSURED] mark=0 use=1"
)
NO_ACCOUNTING = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 "
    "sport=51234 dport=443 src=1.1.1.1 dst=10.0.0.5 sport=443 dport=51234 "
    "[ASSURED] mark=0 use=1"
)


def test_parses_an_accounted_tcp_flow_in_both_directions():
    flow = connections.parse_line(ACCOUNTED_TCP)

    assert flow["proto"] == "tcp"
    assert flow["family"] == "ipv4"
    assert flow["state"] == "ESTABLISHED"
    assert flow["unreplied"] is False
    assert flow["orig"] == {
        "src": "10.0.0.5", "dst": "1.1.1.1", "sport": 51234, "dport": 443,
        "bytes": 1440, "packets": 12,
    }
    assert flow["reply"] == {
        "src": "1.1.1.1", "dst": "10.0.0.5", "sport": 443, "dport": 51234,
        "bytes": 5000, "packets": 10,
    }


def test_udp_has_no_state():
    flow = connections.parse_line(UDP)
    assert flow["proto"] == "udp" and flow["state"] is None
    assert flow["orig"]["dport"] == 53


def test_unreplied_flows_are_flagged():
    flow = connections.parse_line(UNREPLIED)
    assert flow["unreplied"] is True
    assert flow["state"] == "SYN_SENT"


def test_icmp_parses_without_ports():
    flow = connections.parse_line(ICMP)
    assert flow["proto"] == "icmp"
    assert flow["orig"]["sport"] is None and flow["orig"]["dport"] is None
    assert flow["orig"]["bytes"] == 84


def test_ipv6_is_recognised():
    flow = connections.parse_line(IPV6)
    assert flow["family"] == "ipv6" and flow["orig"]["src"] == "fd00::1"


def test_rows_without_accounting_parse_with_no_byte_counts():
    flow = connections.parse_line(NO_ACCOUNTING)
    assert flow["orig"]["bytes"] is None and flow["reply"]["bytes"] is None
    assert flow["orig"]["dport"] == 443


def test_junk_lines_are_skipped():
    assert connections.parse_line("") is None
    assert connections.parse_line("garbage without a protocol") is None
    # A header-ish line with a protocol but no tuple.
    assert connections.parse_line("ipv4 2 tcp 6 431999 ESTABLISHED") is None


def test_parse_skips_what_it_cannot_read():
    text = "\n".join([ACCOUNTED_TCP, "", "nonsense", UDP])
    assert len(connections.parse(text)) == 2


def test_accounting_detection():
    assert connections.has_accounting(connections.parse(ACCOUNTED_TCP)) is True
    assert connections.has_accounting(connections.parse(NO_ACCOUNTING)) is False
    # An empty table can't prove accounting is on, so it reads as off.
    assert connections.has_accounting([]) is False


def test_aggregate_collapses_a_conversation_and_sums_it():
    """Six connections to the same host:port are one conversation."""
    flows = connections.parse("\n".join([ACCOUNTED_TCP] * 6))
    peers, total = connections.aggregate(flows, 50)

    assert total == 1
    (row,) = peers
    assert row["flows"] == 6
    assert row["orig_bytes"] == 1440 * 6
    assert row["reply_bytes"] == 5000 * 6
    assert row["states"] == ["ESTABLISHED"]
    assert row["src"] == "10.0.0.5" and row["dst"] == "1.1.1.1"


def test_aggregate_keeps_different_destinations_apart():
    peers, total = connections.aggregate(
        connections.parse("\n".join([ACCOUNTED_TCP, UDP])), 50
    )
    assert total == 2
    assert {r["dst"] for r in peers} == {"1.1.1.1", "8.8.8.8"}


def test_aggregate_sorts_by_volume_and_truncates():
    flows = connections.parse("\n".join([ACCOUNTED_TCP, UDP, UDP, UDP]))
    peers, total = connections.aggregate(flows, 1)

    assert total == 2
    # 1440+5000 for the TCP conversation beats 3*(64+160) for the DNS one.
    assert len(peers) == 1 and peers[0]["dst"] == "1.1.1.1"


def test_aggregate_falls_back_to_flow_count_without_accounting():
    quiet = NO_ACCOUNTING
    busy = NO_ACCOUNTING.replace("dst=1.1.1.1", "dst=9.9.9.9")
    peers, _ = connections.aggregate(
        connections.parse("\n".join([quiet, busy, busy, busy])), 50
    )
    assert peers[0]["dst"] == "9.9.9.9" and peers[0]["flows"] == 3


def test_attribution_fields_are_present_but_unset():
    """Phase 1 reports the table as it is; naming the container comes next.
    The keys exist now so the dashboard's shape doesn't shift later."""
    peers, _ = connections.aggregate(connections.parse(ACCOUNTED_TCP), 50)
    assert peers[0]["container"] is None
    assert peers[0]["container_id"] is None


def test_snapshot_reads_a_mounted_table(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text("\n".join([ACCOUNTED_TCP, UDP]) + "\n")
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    result = connections.snapshot("bigboy")

    assert result["available"] is True
    assert result["host"] == "bigboy"
    assert result["accounting"] is True
    assert result["flows_total"] == 2
    assert result["conversations_total"] == 2
    assert result["truncated"] is False
    assert result["source"] == str(table)


def test_snapshot_reports_a_missing_table_instead_of_failing(monkeypatch, tmp_path):
    monkeypatch.setenv("CONNTRACK_FILE", str(tmp_path / "nope"))
    monkeypatch.setattr(connections, "default_paths", tuple)

    result = connections.snapshot("bigboy")

    assert result["available"] is False
    assert "mount" in result["reason"]


def test_snapshot_reports_when_accounting_is_off(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(NO_ACCOUNTING + "\n")
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    result = connections.snapshot("bigboy")
    assert result["available"] is True and result["accounting"] is False


def test_snapshot_can_be_switched_off(monkeypatch, tmp_path):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    monkeypatch.setenv("CONNECTIONS_ENABLED", "0")

    result = connections.snapshot("bigboy")
    assert result["available"] is False and "disabled" in result["reason"]


def test_snapshot_is_cached(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    first = connections.snapshot("bigboy")
    table.write_text("\n".join([ACCOUNTED_TCP, UDP]))
    assert connections.snapshot("bigboy")["flows_total"] == first["flows_total"]

    connections.reset_cache()
    assert connections.snapshot("bigboy")["flows_total"] == 2


def test_max_peers_is_configurable(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text("\n".join([ACCOUNTED_TCP, UDP, ICMP]))
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    monkeypatch.setenv("CONNECTIONS_MAX_PEERS", "2")

    result = connections.snapshot("bigboy")
    assert len(result["peers"]) == 2
    assert result["conversations_total"] == 3
    assert result["truncated"] is True


# Shapes seen on real kernels that the positional head parsing has to
# survive: an SELinux host adds secctx=, some kernels add zone= and
# delta-time=, and the pre-3.x format omits the ipv4/ipv6 name entirely.
SELINUX = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 "
    "sport=51234 dport=443 packets=12 bytes=1440 src=1.1.1.1 dst=10.0.0.5 "
    "sport=443 dport=51234 packets=10 bytes=5000 [ASSURED] mark=0 "
    "secctx=system_u:object_r:unlabeled_t:s0 use=1"
)
NO_L3_NAME = (
    "tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 sport=51234 "
    "dport=443 src=1.1.1.1 dst=10.0.0.5 sport=443 dport=51234 "
    "[ASSURED] mark=0 use=1"
)
MULTICAST_UNREPLIED = (
    "ipv4     2 udp      17 10 src=10.0.0.5 dst=239.255.255.250 sport=5353 "
    "dport=1900 packets=2 bytes=200 [UNREPLIED] src=239.255.255.250 "
    "dst=10.0.0.5 sport=1900 dport=5353 packets=0 bytes=0 mark=0 use=1"
)


def test_extra_trailing_fields_do_not_shift_the_tuples():
    flow = connections.parse_line(SELINUX)
    assert flow["orig"]["bytes"] == 1440 and flow["reply"]["bytes"] == 5000
    assert flow["state"] == "ESTABLISHED"


def test_the_older_format_without_an_address_family_still_parses():
    flow = connections.parse_line(NO_L3_NAME)
    assert flow["proto"] == "tcp" and flow["state"] == "ESTABLISHED"
    assert flow["orig"]["dst"] == "1.1.1.1"


def test_an_unreplied_udp_flow_keeps_its_zero_reply():
    flow = connections.parse_line(MULTICAST_UNREPLIED)
    assert flow["unreplied"] is True
    assert flow["orig"]["bytes"] == 200 and flow["reply"]["bytes"] == 0


def test_the_backup_features_host_mount_is_found_without_extra_config(monkeypatch, tmp_path):
    """A host already mounted for backups (-v /:/host:ro) puts the real
    table at <HOST_ROOT>/proc/1/net/nf_conntrack. Nothing else to mount."""
    host_root = tmp_path / "host"
    table = host_root / "proc" / "1" / "net" / "nf_conntrack"
    table.parent.mkdir(parents=True)
    table.write_text(ACCOUNTED_TCP)

    monkeypatch.setenv("HOST_ROOT", str(host_root))

    assert connections.source_path() == table


def test_pid_one_is_used_not_proc_net(monkeypatch):
    """/proc/net is a symlink to /proc/self/net, so a bind-mounted
    /host/proc/net would resolve back to this process's namespace."""
    monkeypatch.setenv("HOST_ROOT", "/host")
    paths = connections.default_paths()

    assert "/host/proc/1/net/nf_conntrack" in paths
    assert "/host/proc/net/nf_conntrack" not in paths


def test_the_narrow_mount_wins_over_the_host_filesystem(monkeypatch, tmp_path):
    monkeypatch.setenv("HOST_ROOT", str(tmp_path))
    assert connections.default_paths()[0] == "/host/nf_conntrack"


def test_an_empty_table_in_our_own_namespace_reads_as_not_set_up(monkeypatch, tmp_path):
    empty = tmp_path / "nf_conntrack"
    empty.write_text("")

    monkeypatch.setattr(connections, "OWN_NAMESPACE_PATH", str(empty))
    monkeypatch.setattr(connections, "default_paths", lambda: (str(empty),))

    result = connections.snapshot("bigboy")

    assert result["available"] is False
    assert "own network namespace" in result["reason"]


def test_a_mounted_table_that_is_empty_still_reports_available(monkeypatch, tmp_path):
    """Only the *fallback* path is treated as suspicious when empty \u2014 a
    deliberately mounted table with nothing in it is just a quiet host."""
    empty = tmp_path / "nf_conntrack"
    empty.write_text("")
    monkeypatch.setenv("CONNTRACK_FILE", str(empty))

    result = connections.snapshot("bigboy")

    assert result["available"] is True
    assert result["flows_total"] == 0


# ---- container attribution ------------------------------------------------

# Docker masquerades outbound: the container's own address is still the
# original source.
OUTBOUND = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=172.18.0.5 dst=140.82.121.4 "
    "sport=44444 dport=443 packets=9 bytes=900 src=140.82.121.4 "
    "dst=192.168.1.10 sport=443 dport=44444 packets=7 bytes=7000 "
    "[ASSURED] mark=0 use=1"
)
# Docker DNATs inbound: the container's address only shows up in the reply.
INBOUND = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.40 dst=192.168.1.10 "
    "sport=51000 dport=8096 packets=620 bytes=51200 src=172.18.0.7 "
    "dst=192.168.1.40 sport=8096 dport=51000 packets=3010 bytes=4294967296 "
    "[ASSURED] mark=0 use=1"
)
# Same bridge, no NAT at all.
CONTAINER_TO_CONTAINER = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=172.18.0.7 dst=172.18.0.9 "
    "sport=55000 dport=5432 packets=40 bytes=4000 src=172.18.0.9 "
    "dst=172.18.0.7 sport=5432 dport=55000 packets=40 bytes=9000 "
    "[ASSURED] mark=0 use=1"
)

CONTAINERS = [
    {"id": "aaa111", "name": "gitsync", "ips": ["172.18.0.5"], "ports": {}},
    {"id": "bbb222", "name": "jellyfin", "ips": ["172.18.0.7"],
     "ports": {(8096, "tcp"): True}},
    {"id": "ccc333", "name": "postgres", "ips": ["172.18.0.9"], "ports": {}},
]


def index():
    return connections.build_index(CONTAINERS)


def only(text):
    peers, _ = connections.aggregate(connections.parse(text), 50, index())
    return peers[0]


def test_outbound_is_matched_on_the_masqueraded_source():
    row = only(OUTBOUND)

    assert row["container"] == "gitsync" and row["container_id"] == "aaa111"
    assert row["direction"] == "out"
    assert row["peer"] == "140.82.121.4" and row["peer_port"] == 443
    # Sent by the container, received by it.
    assert row["tx_bytes"] == 900 and row["rx_bytes"] == 7000


def test_inbound_is_matched_on_the_dnatted_reply_source():
    row = only(INBOUND)

    assert row["container"] == "jellyfin"
    assert row["direction"] == "in"
    assert row["peer"] == "192.168.1.40"
    # The swap that matters: conntrack counted 4 GB in the *reply*, which
    # is the host sending. Reporting orig/reply as rx/tx would invert it.
    assert row["tx_bytes"] == 4294967296
    assert row["rx_bytes"] == 51200


def test_inbound_falls_back_to_the_published_port():
    """Some setups don't leave the container address in the reply tuple."""
    no_reply_ip = INBOUND.replace("src=172.18.0.7", "src=192.168.1.10")
    peers, _ = connections.aggregate(connections.parse(no_reply_ip), 50, index())

    assert peers[0]["container"] == "jellyfin"
    assert peers[0]["direction"] == "in"


def test_a_published_port_of_a_different_protocol_does_not_match():
    udp_index = connections.build_index(
        [{"id": "d4", "name": "dns", "ips": [], "ports": {(8096, "udp"): True}}]
    )
    peers, _ = connections.aggregate(connections.parse(INBOUND), 50, udp_index)
    assert peers[0]["container"] is None


def test_both_ends_are_named_when_both_are_containers():
    row = only(CONTAINER_TO_CONTAINER)

    assert row["container"] == "jellyfin"
    assert row["peer_container"] == "postgres"
    assert row["direction"] == "out"
    assert row["peer_port"] == 5432


def test_host_traffic_is_left_unattributed():
    row = only(ACCOUNTED_TCP)  # 10.0.0.5 -> 1.1.1.1, no container involved

    assert row["container"] is None and row["direction"] is None
    assert row["rx_bytes"] is None and row["tx_bytes"] is None
    # The raw endpoints are still there.
    assert row["src"] == "10.0.0.5" and row["dst"] == "1.1.1.1"


def test_rx_tx_accumulate_across_the_flows_of_one_conversation():
    peers, _ = connections.aggregate(
        connections.parse("\n".join([INBOUND] * 3)), 50, index()
    )
    assert peers[0]["flows"] == 3
    assert peers[0]["tx_bytes"] == 4294967296 * 3
    assert peers[0]["rx_bytes"] == 51200 * 3


def test_without_an_index_nothing_is_attributed():
    peers, _ = connections.aggregate(connections.parse(INBOUND), 50, None)
    assert peers[0]["container"] is None
    assert peers[0]["peer"] is None


def test_container_map_reads_addresses_and_published_ports():
    class FakeContainer:
        short_id = "bbb222"
        name = "jellyfin"
        attrs = {
            "NetworkSettings": {
                "Networks": {"media_default": {"IPAddress": "172.18.0.7"}},
                "IPAddress": "",
            },
            "HostConfig": {
                "PortBindings": {"8096/tcp": [{"HostPort": "8096"}]}
            },
        }

    class FakeClient:
        containers = type("C", (), {"list": staticmethod(lambda: [FakeContainer()])})()

    (entry,) = connections.container_map(FakeClient())

    assert entry["name"] == "jellyfin"
    assert entry["ips"] == ["172.18.0.7"]
    assert entry["ports"] == {(8096, "tcp"): True}


def test_container_map_survives_one_broken_container():
    class Bad:
        short_id = "x"
        name = "bad"

        @property
        def attrs(self):
            raise RuntimeError("gone")

    class Good:
        short_id = "y"
        name = "good"
        attrs = {"NetworkSettings": {"Networks": {}}, "HostConfig": {}}

    class FakeClient:
        containers = type("C", (), {"list": staticmethod(lambda: [Bad(), Good()])})()

    names = [c["name"] for c in connections.container_map(FakeClient())]
    assert names == ["good"]


def test_snapshot_reports_whether_attribution_ran(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(INBOUND)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    assert connections.snapshot("bigboy")["attributed"] is False


def test_a_failing_docker_client_does_not_take_the_table_with_it(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(INBOUND)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    class Boom:
        @property
        def containers(self):
            raise RuntimeError("daemon gone")

    result = connections.snapshot("bigboy", Boom())

    assert result["available"] is True
    assert result["attributed"] is False
    assert result["peers"][0]["container"] is None


# ---- process names for host traffic ---------------------------------------


def test_host_flows_get_a_process_name(tmp_path, monkeypatch):
    """The conntrack row belongs to no container, so it falls through to
    the socket tables: 10.0.0.5:51234 -> 1.1.1.1:443."""
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    monkeypatch.setattr(
        connections.sockets, "read_sockets",
        lambda *a, **k: [{
            "proto": "tcp", "local_ip": "10.0.0.5", "local_port": 51234,
            "remote_ip": "1.1.1.1", "remote_port": 443, "inode": 4242,
        }],
    )
    monkeypatch.setattr(
        connections.sockets, "owners",
        lambda wanted, *a, **k: ({4242: {"pid": 991, "process": "curl"}}, False),
    )

    result = connections.snapshot("bigboy")

    assert result["processes"] is True
    assert result["peers"][0]["process"] == "curl"
    assert result["peers"][0]["pid"] == 991


def test_containers_are_not_looked_up_in_the_socket_tables(tmp_path, monkeypatch):
    """Already named by attribution — no reason to walk every process."""
    table = tmp_path / "nf_conntrack"
    table.write_text(INBOUND)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    called = []
    monkeypatch.setattr(
        connections.sockets, "read_sockets",
        lambda *a, **k: called.append(1) or [],
    )

    class FakeClient:
        containers = type("C", (), {"list": staticmethod(lambda: [])})()

    monkeypatch.setattr(connections, "container_map", lambda client: CONTAINERS)

    result = connections.snapshot("bigboy", FakeClient())

    assert result["peers"][0]["container"] == "jellyfin"
    assert result["peers"][0]["process"] is None
    assert called == []


def test_an_unmatched_host_flow_keeps_a_null_process(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    monkeypatch.setattr(
        connections.sockets, "read_sockets",
        lambda *a, **k: [{
            "proto": "tcp", "local_ip": "10.0.0.5", "local_port": 9,
            "remote_ip": "9.9.9.9", "remote_port": 9, "inode": 1,
        }],
    )
    monkeypatch.setattr(connections.sockets, "owners", lambda *a, **k: ({}, False))

    peer = connections.snapshot("bigboy")["peers"][0]
    assert peer["process"] is None and peer["pid"] is None


def test_unreadable_socket_tables_report_processes_false(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    monkeypatch.setattr(connections.sockets, "read_sockets", lambda *a, **k: [])

    result = connections.snapshot("bigboy")

    assert result["processes"] is False
    assert result["available"] is True  # the table itself is still fine


def test_process_naming_can_be_switched_off(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    monkeypatch.setenv("CONNECTIONS_PROCESSES", "0")

    called = []
    monkeypatch.setattr(
        connections.sockets, "read_sockets", lambda *a, **k: called.append(1) or []
    )

    assert connections.snapshot("bigboy")["processes"] is False
    assert called == []


def test_the_representative_flow_does_not_leak_into_the_response(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    monkeypatch.setattr(connections.sockets, "read_sockets", lambda *a, **k: [])

    assert "_flow" not in connections.snapshot("bigboy")["peers"][0]


def test_a_denied_process_walk_says_why(tmp_path, monkeypatch):
    """The real-world failure: Docker drops CAP_SYS_PTRACE, so the walk is
    refused and nothing is ever named. That used to look identical to
    "these sockets have no owner"."""
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    monkeypatch.setattr(
        connections.sockets, "read_sockets",
        lambda *a, **k: [{
            "proto": "tcp", "local_ip": "10.0.0.5", "local_port": 51234,
            "remote_ip": "1.1.1.1", "remote_port": 443, "inode": 4242,
        }],
    )
    monkeypatch.setattr(connections.sockets, "owners", lambda *a, **k: ({}, True))
    monkeypatch.setattr(connections.sockets, "diagnose", lambda *a, **k: {
        "pids_visible": 200, "fds_readable": 2, "fds_refused": 190,
        "sockets": 40,
        "reason": "refused when reading processes' open sockets — add "
                  "`cap_add: [SYS_PTRACE]` to the agent",
    })

    result = connections.snapshot("bigboy")

    assert result["processes"] is False
    assert result["processes_state"] == "denied"
    assert "SYS_PTRACE" in result["processes_hint"]
    assert result["available"] is True, "the table itself is still fine"


def test_a_working_walk_carries_no_hint(tmp_path, monkeypatch):
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))
    monkeypatch.setattr(
        connections.sockets, "read_sockets",
        lambda *a, **k: [{
            "proto": "tcp", "local_ip": "10.0.0.5", "local_port": 51234,
            "remote_ip": "1.1.1.1", "remote_port": 443, "inode": 4242,
        }],
    )
    monkeypatch.setattr(
        connections.sockets, "owners",
        lambda *a, **k: ({4242: {"pid": 1, "process": "sshd"}}, False),
    )

    result = connections.snapshot("bigboy")

    assert result["processes"] is True
    assert result["processes_hint"] is None


def test_sockets_read_but_nothing_matched_is_its_own_state(tmp_path, monkeypatch):
    """The state that actually happened on the real fleet: the walk works,
    the tables are read, and still nothing resolves. Reporting that as
    "ok" is what made the feature look like it worked."""
    table = tmp_path / "nf_conntrack"
    table.write_text(ACCOUNTED_TCP)
    monkeypatch.setenv("CONNTRACK_FILE", str(table))

    monkeypatch.setattr(
        connections.sockets, "read_sockets",
        lambda *a, **k: [{
            "proto": "tcp", "local_ip": "10.0.0.5", "local_port": 51234,
            "remote_ip": "1.1.1.1", "remote_port": 443, "inode": 4242,
        }],
    )
    monkeypatch.setattr(connections.sockets, "owners", lambda *a, **k: ({}, False))
    monkeypatch.setattr(connections.sockets, "diagnose", lambda *a, **k: {
        "pids_visible": 260, "fds_readable": 82, "fds_refused": 0,
        "sockets": 52, "reason": None,
    })

    result = connections.snapshot("bigboy")

    assert result["processes_state"] == "unmatched"
    assert "260 processes visible" in result["processes_hint"]
    assert "82 with readable sockets" in result["processes_hint"]
    # The evidence travels with it, so nobody has to go collect it.
    assert result["processes_facts"]["sockets"] == 52
