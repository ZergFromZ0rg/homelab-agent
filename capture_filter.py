"""Filter expressions for the packet capture, in the style of tcpdump's
pcap-filter(7) — a subset, evaluated in Python on each decoded packet rather
than compiled to kernel BPF, so a mistake costs a message, not a crash.

    host 192.168.1.10 and port 443
    not (port 22 or port 53)
    tcp dst port 8096 and src net 192.168.1.0/24
    udp portrange 5000-5100
    ether host aa:bb:cc:00:00:01
    icmp or arp
    len > 1000
    tls and sni *.example.com

Primitives:  [proto] [src|dst] host IP · [proto] [src|dst] net CIDR ·
             [tcp|udp] [src|dst] port N · [tcp|udp] [src|dst] portrange A-B ·
             ether [src|dst] host MAC · len <|<=|>|>=|=|== N · less N · greater N ·
             sni NAME (a TLS server name, ``*`` wildcards allowed, ``*.example.com``
             also matches example.com — an addition to pcap-filter, which
             cannot see inside TLS)
Protocols:   tcp udp icmp icmp6 arp ip ip6 dns tls
Combinators: and && · or || · not ! · parentheses

Not supported (and refused with a message rather than guessed at): byte
offsets such as ``tcp[13] & 2``, ``vlan``, ``proto``, ``gateway``.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import Callable

MAX_LENGTH = 300
MAX_DEPTH = 16

PROTOCOLS = {"tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6", "dns", "tls"}
DIRECTIONS = {"src", "dst"}
_TOKEN = re.compile(r"\s*(&&|\|\||<=|>=|==|[()!<>=]|[^\s()!<>=&|]+)")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)
_UNSUPPORTED = {"vlan", "proto", "gateway", "broadcast", "multicast"}

Predicate = Callable[[dict], bool]


class FilterError(ValueError):
    """The expression can't be used; the message says where and why."""


def _tokens(text: str) -> list[str]:
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise FilterError(f"unexpected {text[pos:pos + 8]!r}")
        out.append(match.group(1))
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


def _protocol(name: str) -> Predicate:
    if name == "ip":
        return lambda p: p.get("ip") == 4
    if name == "ip6":
        return lambda p: p.get("ip") == 6
    if name == "icmp6":
        return lambda p: p.get("proto") == "ICMPv6"
    if name in ("dns", "tls"):
        return lambda p: p.get("app") == name
    wanted = name.upper()
    return lambda p: p.get("proto") == wanted


def _address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise FilterError(f"{value!r} isn't an IP address") from error


def _port(value: str) -> int:
    if not value.isdigit() or not 0 < int(value) <= 65535:
        raise FilterError(f"{value!r} isn't a port (1-65535)")
    return int(value)


def _side(direction: str | None, a: str, b: str, test: Callable[[object], bool]) -> Predicate:
    """``test`` applied to field ``a`` (src), ``b`` (dst), or either."""
    if direction == "src":
        return lambda p: p.get(a) is not None and test(p[a])
    if direction == "dst":
        return lambda p: p.get(b) is not None and test(p[b])
    return lambda p: (p.get(a) is not None and test(p[a])) or (p.get(b) is not None and test(p[b]))


def _and(*parts: Predicate | None) -> Predicate:
    active = [p for p in parts if p]
    return lambda pkt: all(p(pkt) for p in active)


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0

    # --- token helpers -------------------------------------------------------

    def peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def take(self) -> str:
        if self.pos >= len(self.tokens):
            raise FilterError("the expression ends too soon")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expect(self, word: str) -> None:
        got = self.take()
        if got.lower() != word:
            raise FilterError(f"expected {word!r}, found {got!r}")

    # --- grammar -------------------------------------------------------------

    def parse(self) -> Predicate:
        if not self.tokens:
            raise FilterError("the filter is empty")
        node = self.or_expr(0)
        if self.pos < len(self.tokens):
            raise FilterError(f"unexpected {self.tokens[self.pos]!r} — join conditions with and / or")
        return node

    def or_expr(self, depth: int) -> Predicate:
        parts = [self.and_expr(depth)]
        while self.peek() in ("or", "||"):
            self.take()
            parts.append(self.and_expr(depth))
        return parts[0] if len(parts) == 1 else (lambda p, ps=parts: any(f(p) for f in ps))

    def and_expr(self, depth: int) -> Predicate:
        parts = [self.unary(depth)]
        while self.peek() in ("and", "&&"):
            self.take()
            parts.append(self.unary(depth))
        return parts[0] if len(parts) == 1 else (lambda p, ps=parts: all(f(p) for f in ps))

    def unary(self, depth: int) -> Predicate:
        if depth > MAX_DEPTH:
            raise FilterError("too many nested parentheses")
        if self.peek() in ("not", "!"):
            self.take()
            inner = self.unary(depth + 1)
            return lambda p: not inner(p)
        if self.peek() == "(":
            self.take()
            inner = self.or_expr(depth + 1)
            if self.peek() != ")":
                raise FilterError("a '(' is never closed")
            self.take()
            return inner
        return self.primitive()

    def primitive(self) -> Predicate:
        first = self.take()
        word = first.lower()
        if word in _UNSUPPORTED or "[" in word:
            raise FilterError(f"{first!r} isn't supported here")

        qualifier: str | None = None
        if word in PROTOCOLS:
            qualifier = word
            nxt = self.peek()
            if nxt not in DIRECTIONS and nxt not in ("host", "net", "port", "portrange"):
                return _protocol(word)  # a bare protocol
            word = self.take().lower()

        if word == "ether":
            return self.ether()
        if word in ("len", "less", "greater"):
            if qualifier:
                raise FilterError(f"{qualifier!r} can't qualify {word!r}")
            return self.length(word)
        if word == "sni":
            if qualifier:
                raise FilterError(f"{qualifier!r} can't qualify 'sni'")
            return self.sni()

        direction = None
        if word in DIRECTIONS:
            direction = word
            word = self.take().lower()

        kind_proto = _protocol(qualifier) if qualifier else None
        if word == "host":
            ip = _address(self.take())
            return _and(kind_proto, _side(direction, "src", "dst", lambda v: v == ip))
        if word == "net":
            spec = self.take()
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError as error:
                raise FilterError(f"{spec!r} isn't a network (try 192.168.1.0/24)") from error

            def inside(value) -> bool:
                try:
                    return ipaddress.ip_address(value) in net
                except ValueError:
                    return False

            return _and(kind_proto, _side(direction, "src", "dst", inside))
        if word in ("port", "portrange"):
            if qualifier in ("icmp", "icmp6", "arp"):
                raise FilterError(f"{qualifier!r} has no ports")
            spec = self.take()
            if word == "port":
                low = high = _port(spec)
            else:
                low_text, dash, high_text = spec.partition("-")
                if not dash:
                    raise FilterError("portrange needs a range such as 5000-5100")
                low, high = _port(low_text), _port(high_text)
                if low > high:
                    raise FilterError(f"{spec!r} runs backwards")
            has_ports = lambda p: p.get("proto") in ("TCP", "UDP")  # noqa: E731
            return _and(kind_proto, has_ports, _side(direction, "sport", "dport", lambda v: low <= v <= high))
        raise FilterError(f"don't know {first!r} — try host, net, port, portrange, a protocol, or len")

    def ether(self) -> Predicate:
        direction = None
        if self.peek() in DIRECTIONS:
            direction = self.take().lower()
        self.expect("host")
        mac = self.take().lower()
        if not _MAC.match(mac):
            raise FilterError(f"{mac!r} isn't a MAC address (aa:bb:cc:dd:ee:ff)")
        return _side(direction, "src_mac", "dst_mac", lambda v: v == mac)

    def length(self, word: str) -> Predicate:
        op = {"less": "<=", "greater": ">="}.get(word)
        if op is None:
            op = self.take()
            if op not in ("<", "<=", ">", ">=", "=", "=="):
                raise FilterError(f"after 'len' use < <= > >= or =, not {op!r}")
        number = self.take()
        if not number.isdigit():
            raise FilterError(f"{number!r} isn't a number")
        n = int(number)
        compare = {
            "<": lambda v: v < n, "<=": lambda v: v <= n, ">": lambda v: v > n,
            ">=": lambda v: v >= n, "=": lambda v: v == n, "==": lambda v: v == n,
        }[op]
        return lambda p: compare(p.get("len", 0))

    def sni(self) -> Predicate:
        pattern = self.take().lower()
        if not re.fullmatch(r"[a-z0-9*._-]{1,253}", pattern):
            raise FilterError(f"{pattern!r} isn't a host name")
        bare = pattern[2:] if pattern.startswith("*.") else None  # *.example.com covers example.com too

        def named(p: dict) -> bool:
            name = (p.get("sni") or "").lower()
            return bool(name) and (fnmatch.fnmatchcase(name, pattern) or name == bare)

        return named


def compile_filter(text: str) -> Predicate:
    """A predicate over a decoded packet, or FilterError."""
    text = (text or "").strip()
    if len(text) > MAX_LENGTH:
        raise FilterError(f"the filter is longer than {MAX_LENGTH} characters")
    return _Parser(_tokens(text)).parse()
