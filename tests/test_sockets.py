import os
import pytest

import sockets

# Real /proc/net/tcp shape. Column 3 is the state: 01 established,
# 0A listening. Column 9 is the inode.
TCP_TABLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0F02000A:0016 0102000A:E2B4 01 00000000:00000000 02:000AFAF0 00000000     0        0 31337 1 0000 20 0 0 10 -1
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000 10 0 0 10 -1
   2: 0F02000A:C350 08080808:01BB 01 00000000:00000000 02:000AFAF0 00000000  1000        0 44444 1 0000 20 0 0 10 -1
"""

UDP_TABLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  512: 0F02000A:E3B0 01010101:0035 01 00000000:00000000 00:00000000 00000000   999        0 55555 2 0000 0
"""

TCP6_TABLE = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000001000000:C351 01 00000000:00000000 02:000AFAF0 00000000     0        0 66666 1 0000 20 0 0 10 -1
"""


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("CONNECTIONS_PROCESSES", raising=False)
    monkeypatch.delenv("HOST_PROC", raising=False)
    monkeypatch.delenv("HOST_ROOT", raising=False)
    yield


# ---- address decoding -----------------------------------------------------


def test_ipv4_addresses_are_byte_reversed():
    """The kernel prints each 32-bit word in host byte order."""
    assert sockets.parse_address("0F02000A:0016") == ("10.0.2.15", 22)
    assert sockets.parse_address("0100007F:0035") == ("127.0.0.1", 53)
    assert sockets.parse_address("00000000:0050") == ("0.0.0.0", 80)


def test_ipv6_addresses_are_reversed_within_each_word():
    address, port = sockets.parse_address(
        "00000000000000000000000001000000:1F90"
    )
    assert address == "::1" and port == 8080


def test_a_malformed_address_is_not_fatal():
    assert sockets.parse_address("garbage") == (None, None)
    assert sockets.parse_address("ZZZZ:0050") == (None, 80)


# ---- table parsing --------------------------------------------------------


def test_only_established_tcp_sockets_are_kept():
    """A listener has no peer to match a flow against."""
    rows = sockets.parse_socket_table(TCP_TABLE, "tcp")

    assert [r["inode"] for r in rows] == [31337, 44444]
    assert rows[0]["local_ip"] == "10.0.2.15" and rows[0]["local_port"] == 22
    assert rows[0]["remote_ip"] == "10.0.2.1" and rows[0]["remote_port"] == 58036


def test_udp_rows_are_kept_regardless_of_state():
    (row,) = sockets.parse_socket_table(UDP_TABLE, "udp")
    assert row["inode"] == 55555 and row["remote_port"] == 53


def test_ipv6_tables_parse():
    (row,) = sockets.parse_socket_table(TCP6_TABLE, "tcp")
    assert row["local_ip"] == "::1" and row["inode"] == 66666


def test_the_header_and_short_lines_are_skipped():
    assert sockets.parse_socket_table("header only\n", "tcp") == []
    assert sockets.parse_socket_table("hdr\n 0: junk\n", "tcp") == []


def test_sockets_with_no_inode_are_dropped():
    zeroed = TCP_TABLE.replace(" 31337 ", " 0 ")
    assert [r["inode"] for r in sockets.parse_socket_table(zeroed, "tcp")] == [44444]


# ---- matching a flow onto a socket ----------------------------------------


def flow(proto="tcp", src="10.0.2.15", sport=50000, dst="8.8.8.8", dport=443):
    return {
        "proto": proto,
        "orig": {"src": src, "dst": dst, "sport": sport, "dport": dport,
                 "bytes": None, "packets": None},
        "reply": {"src": dst, "dst": src, "sport": dport, "dport": sport,
                  "bytes": None, "packets": None},
    }


def index():
    return sockets.build_index(
        sockets.parse_socket_table(TCP_TABLE, "tcp")
        + sockets.parse_socket_table(UDP_TABLE, "udp")
    )


def test_an_outbound_flow_matches_on_its_source_port():
    # Socket 44444 is 10.0.2.15:50000 -> 8.8.8.8:443.
    assert sockets.match(flow(sport=50000, dst="8.8.8.8", dport=443), index()) == 44444


def test_an_inbound_flow_matches_on_its_destination_port():
    # Socket 31337 is 10.0.2.15:22 <- 10.0.2.1:58036.
    inbound = flow(src="10.0.2.1", sport=58036, dst="10.0.2.15", dport=22)
    assert sockets.match(inbound, index()) == 31337


def test_udp_matches_too():
    dns = flow(proto="udp", sport=58288, dst="1.1.1.1", dport=53)
    assert sockets.match(dns, index()) == 55555


def test_the_port_alone_is_a_fallback_when_the_peer_differs():
    """A UDP socket that has spoken to more than one peer still resolves."""
    other_peer = flow(proto="udp", sport=58288, dst="9.9.9.9", dport=53)
    assert sockets.match(other_peer, index()) == 55555


def test_an_unrelated_flow_matches_nothing():
    assert sockets.match(flow(sport=1, dport=2), index()) is None


def test_a_flow_without_ports_matches_nothing():
    icmp = flow(proto="icmp", sport=None, dport=None)
    assert sockets.match(icmp, index()) is None


# ---- owner lookup ---------------------------------------------------------


def fake_proc(tmp_path, processes):
    """A /proc tree: {pid: (comm, [inodes])}."""
    for pid, (comm, inodes) in processes.items():
        pid_dir = tmp_path / str(pid)
        (pid_dir / "fd").mkdir(parents=True)
        (pid_dir / "comm").write_text(comm + "\n")
        for i, inode in enumerate(inodes):
            os.symlink(f"socket:[{inode}]", pid_dir / "fd" / str(i))
    # Things that aren't processes, which the walk has to ignore.
    (tmp_path / "meminfo").write_text("MemTotal: 1 kB\n")
    (tmp_path / "net").mkdir()
    return str(tmp_path)


def test_owners_maps_inodes_to_process_names(tmp_path):
    root = fake_proc(tmp_path, {
        812: ("sshd", [31337]),
        1455: ("curl", [44444, 99999]),
    })

    found, denied = sockets.owners({31337, 44444}, root)
    assert denied is False

    assert found[31337] == {"pid": 812, "process": "sshd"}
    assert found[44444] == {"pid": 1455, "process": "curl"}


def test_owners_ignores_inodes_nobody_asked_for(tmp_path):
    root = fake_proc(tmp_path, {812: ("sshd", [31337, 55555])})
    assert set(sockets.owners({31337}, root)[0]) == {31337}


def test_owners_is_a_no_op_without_wanted_inodes(tmp_path):
    assert sockets.owners(set(), fake_proc(tmp_path, {1: ("init", [1])})) == ({}, False)


def test_owners_survives_a_process_exiting_mid_walk(tmp_path):
    root = fake_proc(tmp_path, {812: ("sshd", [31337]), 99: ("gone", [])})
    (tmp_path / "99" / "fd").rmdir()

    assert sockets.owners({31337}, root)[0][31337]["pid"] == 812


def test_owners_handles_a_process_with_no_comm(tmp_path):
    root = fake_proc(tmp_path, {812: ("sshd", [31337])})
    (tmp_path / "812" / "comm").unlink()

    assert sockets.owners({31337}, root)[0] == {31337: {"pid": 812, "process": None}}


def test_owners_returns_nothing_for_an_unreadable_root():
    assert sockets.owners({1}, "/definitely/not/here") == ({}, False)


def test_the_walk_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(sockets, "MAX_PROCESSES", 2)
    root = fake_proc(tmp_path, {1: ("a", [1]), 2: ("b", [2]), 3: ("c", [3])})

    # Sorted order means 1 and 2 are walked, 3 is past the cap.
    assert set(sockets.owners({1, 2, 3}, root)[0]) == {1, 2}


# ---- where /proc comes from ----------------------------------------------


def test_the_backup_mount_is_preferred_over_our_own_proc(tmp_path, monkeypatch):
    host = tmp_path / "host"
    (host / "proc" / "1").mkdir(parents=True)
    monkeypatch.setenv("HOST_ROOT", str(host))

    assert sockets.proc_root() == str(host / "proc")


def test_an_explicit_override_wins(monkeypatch):
    monkeypatch.setenv("HOST_PROC", "/somewhere/proc")
    assert sockets.proc_root() == "/somewhere/proc"


def test_it_falls_back_to_our_own_proc(monkeypatch, tmp_path):
    monkeypatch.setenv("HOST_ROOT", str(tmp_path / "absent"))
    assert sockets.proc_root() == "/proc"


def test_process_naming_can_be_switched_off(monkeypatch):
    assert sockets.enabled() is True
    monkeypatch.setenv("CONNECTIONS_PROCESSES", "0")
    assert sockets.enabled() is False


def test_a_refused_walk_is_reported_as_denied(tmp_path):
    """Docker drops CAP_SYS_PTRACE, so reading another process's fds is
    refused. Swallowing that as "no owner" made the whole feature look
    like it worked while naming nothing."""
    root = fake_proc(tmp_path, {812: ("sshd", [31337]), 99: ("other", [1])})

    for pid in ("812", "99"):
        (tmp_path / pid / "fd").chmod(0o000)

    try:
        found, denied = sockets.owners({31337}, root)
    finally:
        for pid in ("812", "99"):
            (tmp_path / pid / "fd").chmod(0o755)

    assert found == {}
    assert denied is True


def test_a_few_vanished_processes_are_not_denial(tmp_path):
    """Processes come and go; that's normal and must not read as a
    capability problem."""
    root = fake_proc(tmp_path, {1: ("gone", []), 2: ("b", [2]), 3: ("c", [31337])})
    (tmp_path / "1" / "fd").rmdir()

    found, denied = sockets.owners({31337}, root)

    assert found[31337]["process"] == "c"
    assert denied is False
