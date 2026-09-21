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
