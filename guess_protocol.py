import socket
import struct


DNS_QUERY = (
    b"\x12\x34"
    b"\x01\x00"
    b"\x00\x01"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x07example\x03com\x00"
    b"\x00\x01"
    b"\x00\x01"
)


def send_tcp_probe(ip, port, payload, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(payload)
            return sock.recv(1024)
    except Exception:
        return b""


def send_udp_probe(ip, port, payload, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(1024)
            return data
    except Exception:
        return b""


def guess_protocol(ip, proto, port, timeout):
    http_payload = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
    echo_payload = b"hello_echo_test_123"
    if proto == "tcp":
        resp = send_tcp_probe(ip, port, http_payload, timeout)
        if resp.startswith(b"HTTP/"):
            return "HTTP"

        tcp_dns_payload = struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY
        resp = send_tcp_probe(ip, port, tcp_dns_payload, timeout)
        if len(resp) >= 14 and resp[2:4] == b"\x12\x34" and (resp[4] & 0x80) != 0:
            return "DNS"

        resp = send_tcp_probe(ip, port, echo_payload, timeout)
        if resp == echo_payload:
            return "ECHO"

    elif proto == "udp":
        resp = send_udp_probe(ip, port, DNS_QUERY, timeout)
        if len(resp) >= 12 and resp[:2] == b"\x12\x34" and (resp[2] & 0x80) != 0:
            return "DNS"

        resp = send_udp_probe(ip, port, http_payload, timeout)
        if resp.startswith(b"HTTP/"):
            return "HTTP"

        resp = send_udp_probe(ip, port, echo_payload, timeout)
        if resp == echo_payload:
            return "ECHO"

    return "-"