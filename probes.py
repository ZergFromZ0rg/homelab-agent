"""The probes behind service checks: one function per check type.

Self-contained on purpose (standard library + ``requests``): the dashboard runs
them itself, and the agent on each host carries a verbatim copy so a check can
be run "from" that host. The canonical copy is ``backend/probes.py`` in the
dashboard repo; edit it there and copy it over, don't fork it.

    http     GET a URL; up if it answers with the expected status (default:
             any non-error, i.e. < 400 after redirects). Latency = time to
             response headers.
    keyword  like http, and the page must also contain (or, inverted, must
             NOT contain) some text. Latency = time to download the page.
    ping     one ICMP echo to an IPv4 host. Latency = round trip.
    tcp      open a TCP connection to host:port. Latency = connect time.
    dns      resolve a hostname with this machine's resolver. Latency = lookup.
    tls      TLS handshake to host[:port]; up while the certificate has at
             least ``warn_days`` left. Latency = handshake.

A probe never raises: any failure is a failed ``Result``.
"""

from __future__ import annotations

import logging
import random
import socket
import ssl
import struct
import tempfile
import time
import warnings
from dataclasses import dataclass

import requests

log = logging.getLogger("probes")

MAX_DETAIL_LENGTH = 200
# How much of a page a keyword check reads before giving up on finding text.
MAX_BODY_BYTES = 512 * 1024
DEFAULT_WARN_DAYS = 14

USER_AGENT = "homelab-dashboard/1.0 (service check)"
MAX_REDIRECTS = 5

PROBE_TYPES = ("http", "keyword", "ping", "tcp", "dns", "tls")

@dataclass
class Result:
    ok: bool
    ms: float | None = None
    detail: str | None = None
    # The probe couldn't be run at all (the dashboard couldn't reach the host
    # it was asked to probe from), so this says nothing about the target.
    inconclusive: bool = False
    # Ping with several echoes: the share that got no answer (percent) and the
    # average change in round trip from one answer to the next (ms).
    loss: float | None = None
    jitter: float | None = None


def _short(text: object) -> str:
    return " ".join(str(text).split())[:MAX_DETAIL_LENGTH]


def _read_text(response, started: float, timeout: float) -> tuple[str, bool]:
    """Read up to MAX_BODY_BYTES of a response as text. -> (text, truncated).
    Raises TimeoutError if the whole read takes longer than ``timeout``, so
    a server that trickles bytes can't hold a check open forever."""
    chunks: list[bytes] = []
    size = 0
    truncated = False

    for chunk in response.iter_content(chunk_size=16384):
        if time.perf_counter() - started > timeout:
            raise TimeoutError
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY_BYTES:
            truncated = True
            break

    return b"".join(chunks)[:MAX_BODY_BYTES].decode("utf-8", errors="replace"), truncated


def _keyword_result(spec: dict, code: int, text: str, truncated: bool, ms: float) -> Result:
    keyword = spec["keyword"]
    shown = keyword if len(keyword) <= 40 else keyword[:37] + "..."
    found = keyword.lower() in text.lower()

    if spec["keyword_mode"] == "absent":
        if found:
            return Result(False, ms, _short(f'HTTP {code} · unwanted text "{shown}" found'))
        return Result(True, ms, _short(f'HTTP {code} · "{shown}" not present'))

    if found:
        return Result(True, ms, _short(f'HTTP {code} · found "{shown}"'))
    where = f" in the first {MAX_BODY_BYTES // 1024} KB" if truncated else ""
    return Result(False, ms, _short(f'HTTP {code} · "{shown}" not found{where}'))


def _probe_http(spec: dict) -> Result:
    timeout = spec["timeout"]
    keyword_check = spec["type"] == "keyword"
    started = time.perf_counter()

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    session.headers["User-Agent"] = USER_AGENT

    try:
        with warnings.catch_warnings():
            # Self-signed certs are normal on a LAN; the user opted out of
            # verification on this check, so don't spam the log about it.
            warnings.simplefilter("ignore")
            response = session.get(
                spec["target"],
                timeout=(timeout, timeout),
                verify=spec.get("verify_tls", True),
                allow_redirects=True,
                stream=True,  # headers first; never download a big body blindly
            )

        code = response.status_code
        expected = spec.get("expect_status")
        status_ok = code == expected if expected else code < 400

        if keyword_check and status_ok:
            text, truncated = _read_text(response, started, timeout)
            ms = (time.perf_counter() - started) * 1000
            return _keyword_result(spec, code, text, truncated, ms)

        ms = (time.perf_counter() - started) * 1000
        response.close()
    except requests.exceptions.SSLError as error:
        return Result(False, None, _short(f"TLS error: {error}"))
    except (requests.exceptions.Timeout, TimeoutError):
        return Result(False, None, f"timed out after {timeout:g}s")
    except requests.exceptions.TooManyRedirects:
        return Result(False, None, "too many redirects")
    except requests.exceptions.ConnectionError as error:
        return Result(False, None, _short(_connection_reason(error)))
    except requests.RequestException as error:
        return Result(False, None, _short(error))
    finally:
        session.close()

    detail = f"HTTP {code} (expected {expected})" if expected and not status_ok else f"HTTP {code}"
    return Result(status_ok, ms, detail)


def _connection_reason(error: Exception) -> str:
    text = str(error)
    if "Name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text:
        return "DNS lookup failed"
    if "Connection refused" in text:
        return "connection refused"
    if "Connection reset" in text:
        return "connection reset"
    return f"connection failed: {text}"


def _probe_tcp(spec: dict) -> Result:
    host, _, port = spec["target"].rpartition(":")
    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, int(port)), timeout=spec["timeout"])
    except socket.gaierror:
        return Result(False, None, "DNS lookup failed")
    except (socket.timeout, TimeoutError):
        return Result(False, None, f"timed out after {spec['timeout']:g}s")
    except ConnectionRefusedError:
        return Result(False, None, "connection refused")
    except OSError as error:
        return Result(False, None, _short(error))
    ms = (time.perf_counter() - started) * 1000
    sock.close()
    return Result(True, ms, "connected")


def _probe_dns(spec: dict) -> Result:
    started = time.perf_counter()
    try:
        answers = socket.getaddrinfo(spec["target"], None)
    except socket.gaierror as error:
        return Result(False, None, _short(f"lookup failed: {error.strerror or error}"))
    except OSError as error:
        return Result(False, None, _short(error))
    ms = (time.perf_counter() - started) * 1000
    address = answers[0][4][0] if answers else "?"
    return Result(bool(answers), ms, f"resolved to {address}")


def _decode_der_not_after(der: bytes) -> float:
    """notAfter of a certificate we didn't validate (self-signed LAN
    services), via the stdlib's own decoder, which only reads files."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as handle:
        handle.write(pem)
        handle.flush()
        info = ssl._ssl._test_decode_cert(handle.name)  # noqa: SLF001
    return ssl.cert_time_to_seconds(info["notAfter"])


def _probe_tls(spec: dict) -> Result:
    host, _, port = spec["target"].rpartition(":")
    timeout = spec["timeout"]
    verify = spec.get("verify_tls", True)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                ms = (time.perf_counter() - started) * 1000
                if verify:
                    not_after = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
                else:
                    not_after = _decode_der_not_after(tls.getpeercert(binary_form=True))
    except ssl.SSLCertVerificationError as error:
        reason = error.verify_message or str(error)
        if "expired" in reason:
            return Result(False, None, "certificate has expired")
        return Result(
            False, None,
            _short(f"certificate not trusted: {reason} — accept a self-signed certificate if that's expected"),
        )
    except socket.gaierror:
        return Result(False, None, "DNS lookup failed")
    except (socket.timeout, TimeoutError):
        return Result(False, None, f"timed out after {timeout:g}s")
    except ConnectionRefusedError:
        return Result(False, None, "connection refused")
    except (ssl.SSLError, OSError, KeyError, ValueError) as error:
        return Result(False, None, _short(f"TLS failed: {error}"))

    days = int((not_after - time.time()) // 86400)
    when = time.strftime("%b %-d, %Y", time.gmtime(not_after))
    if days < 0:
        return Result(False, None, f"expired {-days} days ago")
    if days < (spec.get("warn_days") or DEFAULT_WARN_DAYS):
        return Result(False, ms, f"only {days} days left · expires {when}")
    return Result(True, ms, f"{days} days left · expires {when}")


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo_request(ident: int, seq: int, payload: bytes = b"homelab-dashboard") -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    checksum = _icmp_checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, checksum, ident, seq) + payload


def _icmp_body(packet: bytes) -> bytes:
    """The ICMP message inside whatever a socket handed back: raw sockets
    (and macOS datagram ones) include the IPv4 header, Linux datagram ones
    don't. An IPv4 header starts 0x4N; no ICMP message we care about does."""
    if packet and packet[0] >> 4 == 4:
        return packet[(packet[0] & 0x0F) * 4:]
    return packet


def _open_icmp_socket() -> tuple[socket.socket, bool]:
    """-> (socket, is_raw). Unprivileged datagram ICMP first (Linux needs the
    container's net.ipv4.ping_group_range to include its gid; macOS just
    works), then a raw socket (root with CAP_NET_RAW)."""
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP), False
    except OSError:
        pass
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP), True


ICMP_DENIED = (
    "ICMP isn't permitted for the dashboard container (needs "
    "net.ipv4.ping_group_range or CAP_NET_RAW) — use a Port check instead"
)


# Echoes in a burst go out this far apart, so they sample the link over about a
# second rather than hitting one instant; the burst has to fit in the timeout.
PING_GAP = 0.2
MAX_PING_COUNT = 10


def _jitter(rtts: list[float]) -> float | None:
    """Mean change between consecutive round trips (ms); None below two."""
    if len(rtts) < 2:
        return None
    return sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1)


def _burst_result(rtts: list[float | None], timeout: float, address: str) -> Result:
    """``rtts`` is one entry per echo sent, in order; None = never answered."""
    answered = [r for r in rtts if r is not None]
    if not answered:
        return Result(False, None, f"no reply within {timeout:g}s", loss=100.0)
    jitter = _jitter(answered)
    detail = f"{len(answered)}/{len(rtts)} replies from {address}"
    if jitter is not None:
        detail += f" · jitter {jitter:.1f} ms"
    return Result(
        True,
        sum(answered) / len(answered),
        detail,
        loss=round(100.0 * (len(rtts) - len(answered)) / len(rtts), 1),
        jitter=jitter,
    )


def _probe_ping_burst(spec: dict) -> Result:
    """``count`` echoes, ``PING_GAP`` apart, all inside the timeout. Up if any
    answers; loss and jitter say how well."""
    host = spec["target"]
    timeout = spec["timeout"]
    count = max(1, min(int(spec["count"]), MAX_PING_COUNT, int(timeout / PING_GAP)))

    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror:
        return Result(False, None, "DNS lookup failed (IPv4 only)")

    try:
        sock, raw = _open_icmp_socket()
    except OSError:
        return Result(False, None, ICMP_DENIED)

    ident = random.randrange(1, 0xFFFF)
    first = random.randrange(1, 0xFFFF - count)
    seqs = [first + i for i in range(count)]
    sent: dict[int, float] = {}
    rtt: dict[int, float] = {}
    started = time.perf_counter()
    deadline = started + timeout

    try:
        while True:
            now = time.perf_counter()
            while len(sent) < count and now - started >= len(sent) * PING_GAP:
                seq = seqs[len(sent)]
                try:
                    sock.sendto(_echo_request(ident, seq), (address, 0))
                except PermissionError:
                    return Result(False, None, ICMP_DENIED)
                except OSError as error:
                    return Result(False, None, _short(f"send failed: {error}"))
                sent[seq] = time.perf_counter()
            if len(rtt) == count or now >= deadline:
                break

            due = started + len(sent) * PING_GAP if len(sent) < count else deadline
            sock.settimeout(max(0.001, min(due, deadline) - now))
            try:
                data, _ = sock.recvfrom(1024)
            except (socket.timeout, TimeoutError):
                continue
            except OSError as error:
                return Result(False, None, _short(f"receive failed: {error}"))

            arrived = time.perf_counter()
            message = _icmp_body(data)
            if len(message) < 8:
                continue
            kind, _code, _sum, got_ident, got_seq = struct.unpack("!BBHHH", message[:8])
            if kind == 0 and got_seq in sent and got_seq not in rtt and (not raw or got_ident == ident):
                rtt[got_seq] = (arrived - sent[got_seq]) * 1000
            elif kind == 3:
                return Result(False, None, "host unreachable")
            elif kind == 11:
                return Result(False, None, "TTL exceeded in transit")
    finally:
        sock.close()

    return _burst_result([rtt.get(seq) for seq in seqs], timeout, address)


def _probe_ping(spec: dict) -> Result:
    if (spec.get("count") or 1) > 1:
        return _probe_ping_burst(spec)
    host = spec["target"]
    timeout = spec["timeout"]

    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror:
        return Result(False, None, "DNS lookup failed (IPv4 only)")

    try:
        sock, raw = _open_icmp_socket()
    except OSError:
        return Result(False, None, ICMP_DENIED)

    ident = random.randrange(1, 0xFFFF)
    seq = random.randrange(1, 0xFFFF)

    try:
        started = time.perf_counter()
        try:
            sock.sendto(_echo_request(ident, seq), (address, 0))
        except PermissionError:
            return Result(False, None, ICMP_DENIED)
        except OSError as error:
            return Result(False, None, _short(f"send failed: {error}"))

        while True:
            remaining = timeout - (time.perf_counter() - started)
            if remaining <= 0:
                return Result(False, None, f"no reply within {timeout:g}s")
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(1024)
            except (socket.timeout, TimeoutError):
                return Result(False, None, f"no reply within {timeout:g}s")
            except OSError as error:
                return Result(False, None, _short(f"receive failed: {error}"))

            message = _icmp_body(data)
            if len(message) < 8:
                continue
            kind, _code, _sum, got_ident, got_seq = struct.unpack("!BBHHH", message[:8])
            if kind == 0 and got_seq == seq and (not raw or got_ident == ident):
                ms = (time.perf_counter() - started) * 1000
                return Result(True, ms, f"reply from {address}")
            if kind == 3:
                return Result(False, None, "host unreachable")
            if kind == 11:
                return Result(False, None, "TTL exceeded in transit")
    finally:
        sock.close()


def probe(spec: dict) -> Result:
    """Run one check once. Never raises: any failure is a failed Result."""
    try:
        return {
            "http": _probe_http,
            "keyword": _probe_http,
            "ping": _probe_ping,
            "tcp": _probe_tcp,
            "dns": _probe_dns,
            "tls": _probe_tls,
        }[spec["type"]](spec)
    except Exception as error:  # noqa: BLE001 - a probe must not kill its worker
        log.warning("check %s crashed: %s", spec.get("name"), error)
        return Result(False, None, _short(f"probe error: {error}"))


