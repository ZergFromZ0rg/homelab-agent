"""Everything the sniffers decode came off a network, so none of it can be
trusted to be well formed. This feeds the decoders truncated, corrupted and
random frames (the seed is fixed, so a failure is reproducible) and demands that
nothing raises: a packet nobody expected must be shown or skipped, never crash.

The sniffer loop also guards against an exception (one packet, one traceback),
but an exception reaching it still costs that packet its place in the capture —
a DNS reply cut off inside an address record used to disappear that way.
"""

import random
import socket
import struct

import capture_filter as cf
import capture_worker as w
import netwatch_worker as nw

ROUNDS = 1500


def _rand_mac(rng):
    return bytes(rng.randrange(256) for _ in range(6))


def _ip4(rng, proto, payload):
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       bytes(rng.randrange(256) for _ in range(4)), bytes(rng.randrange(256) for _ in range(4)))
    return head + payload


def _dns_reply():
    question = b"\x07example\x03com\x00"
    return (struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0) + question + struct.pack("!HH", 1, 1)
            + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
            + b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + bytes(16))


def _seeds(rng):
    eth = lambda kind, body: _rand_mac(rng) + _rand_mac(rng) + struct.pack("!H", kind) + body  # noqa: E731
    tls = b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00\x00\x0c\x00\x00\x00\x08\x00\x06\x00\x00\x03a.b"
    dhcp = bytes(236) + b"\x63\x82\x53\x63" + bytes([53, 1, 2, 54, 4, 1, 2, 3, 4, 12, 3]) + b"abc\xff"
    return [
        eth(0x0800, _ip4(rng, 6, struct.pack("!HHIIBBHHH", 5, 443, 1, 0, 5 << 4, 0x18, 100, 0, 0) + b"GET /a?b=c HTTP/1.1\r\nHost: x\r\n\r\n")),
        eth(0x0800, _ip4(rng, 6, struct.pack("!HHIIBBHHH", 5, 443, 1, 0, 5 << 4, 0x18, 100, 0, 0) + tls)),
        eth(0x0800, _ip4(rng, 17, struct.pack("!HHHH", 5, 53, 8 + len(_dns_reply()), 0) + _dns_reply())),
        eth(0x0800, _ip4(rng, 17, struct.pack("!HHHH", 68, 67, 8 + len(dhcp), 0) + dhcp)),
        eth(0x0800, _ip4(rng, 17, struct.pack("!HHHH", 123, 123, 56, 0) + bytes([0x24, 2]) + bytes(46))),
        eth(0x0800, _ip4(rng, 1, bytes([8, 0, 0, 0, 0, 0, 0, 0]))),
        eth(0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, _rand_mac(rng), bytes(4), bytes(6), bytes(4))),
        eth(0x86DD, bytes([0x60, 0, 0, 0, 0, 20, 6, 64]) + bytes(32) + struct.pack("!HHIIBBHHH", 1, 2, 3, 4, 5 << 4, 2, 0, 0, 0)),
        eth(0x8100, struct.pack("!HH", 5, 0x0800) + _ip4(rng, 17, bytes(20))),
        _ip4(rng, 17, struct.pack("!HHHH", 123, 123, 56, 0) + bytes(48)),  # a tunnel frame: no Ethernet header
    ]


def _mutations(rng, seed):
    for _ in range(ROUNDS):
        frame = bytearray(seed)
        roll = rng.random()
        if roll < 0.3:
            frame = frame[: rng.randrange(len(frame) + 1)]  # cut off anywhere
        elif roll < 0.75:
            for _ in range(rng.randrange(1, 7)):  # corrupt a few bytes
                if frame:
                    frame[rng.randrange(len(frame))] = rng.randrange(256)
        else:
            frame = bytearray(rng.randrange(256) for _ in range(rng.randrange(0, 140)))  # noise
        yield bytes(frame)


def test_no_frame_makes_a_decoder_raise():
    rng = random.Random(20261008)
    filters = [cf.compile_filter(e) for e in ("tcp and port 443", "dns or tls", "net 192.168.0.0/16", "problem",
                                              "sni *.example.com", "name *.lan", "ether host aa:bb:cc:00:00:01", "len > 60")]
    health = w.TcpHealth()
    decoded = 0
    for seed in _seeds(rng):
        for frame in _mutations(rng, seed):
            for hatype in (1, 65534):
                pkt = w.decode_frame(frame, hatype)  # the one that matters: must not raise
                if pkt is None:
                    continue
                decoded += 1
                nw.events_from(pkt)
                health.check(pkt)
                w.flow_key(pkt)
                w.service(pkt)
                for predicate in filters:
                    predicate(pkt)
    assert decoded > 10_000  # the corpus really did exercise the decoders, not just fail to parse


def test_a_dns_reply_cut_off_inside_an_address_is_shown_not_dropped():
    reply = _dns_reply()
    packet = None
    for cut in range(len(reply) - 30, len(reply)):  # every truncation through the second answer
        body = reply[:cut]
        frame = (bytes(12) + b"\x08\x00" + _ip4(random.Random(1), 17, struct.pack("!HHHH", 53, 4000, 8 + len(body), 0) + body))
        packet = w.decode_frame(frame, 1)
        assert packet is not None and packet["app"] == "dns", cut
    assert w.parse_dns(reply[:-10])[1][0] == ["example.com", "1.2.3.4"]  # the complete first answer still names its address
    assert packet is not None


def test_the_fuzz_corpus_is_deterministic():
    one = [f for s in _seeds(random.Random(5)) for f in list(_mutations(random.Random(6), s))[:5]]
    two = [f for s in _seeds(random.Random(5)) for f in list(_mutations(random.Random(6), s))[:5]]
    assert one == two
    assert socket  # imported for the frames above
