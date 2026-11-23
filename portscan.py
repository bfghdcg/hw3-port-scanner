from parser import parse_arguments, parse_ports
from guess_protocol import guess_protocol
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr1, send
from scapy.config import conf
from scapy.volatile import RandShort
import time
from concurrent.futures import ThreadPoolExecutor


def scan_tcp_port(ip, port, timeout):
    packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")

    start_time = time.perf_counter()
    response = sr1(packet, timeout=timeout, verbose=0)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000)
    if response is not None and response.haslayer(TCP) and response[TCP].flags == "SA":
        rst = IP(dst=ip) / TCP(
            sport=packet[TCP].sport,
            dport=port,
            flags="R",
            seq=response[TCP].ack)

        send(rst, verbose=0)
        return True, elapsed_ms
    else:
        return False, elapsed_ms


def scan_udp_port(ip, port, timeout):
    packet = IP(dst=ip) / UDP(sport=RandShort(), dport=port)
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is not None and response.haslayer(ICMP):
        if response[ICMP].type == 3:
            return False
    return True


def check_target(ip, proto, port, timeout, need_guess):
    proto = proto.lower()
    if proto == "tcp":
        is_open, elapsed_ms = scan_tcp_port(ip, port, timeout)
        if not is_open:
            return None
        protocol_name = guess_protocol(ip, proto, port, timeout) if need_guess else "-"
        return "TCP", port, elapsed_ms, protocol_name

    if proto == "udp":
        is_open = scan_udp_port(ip, port, timeout)
        if not is_open:
            return None
        protocol_name = guess_protocol(ip, proto, port, timeout) if need_guess else "-"
        return "UDP", port, None, protocol_name

    return None

def scan_ports():
    args = parse_arguments()
    ports = parse_ports(args.targets)
    conf.verb = 0
    tasks = []
    for port in sorted(ports["tcp"]):
        tasks.append((args.ip_address, "tcp", port, args.timeout, args.guess))
    for port in sorted(ports["udp"]):
        tasks.append((args.ip_address, "udp", port, args.timeout, args.guess))

    with ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        results = executor.map(lambda task: check_target(*task), tasks)
        for res in results:
            if res is not None:
                proto, port, elapsed_ms, protocol_name = res
                parts = [proto, str(port)]
                if args.verbose and elapsed_ms is not None:
                    parts.append(str(elapsed_ms))
                if args.guess:
                    parts.append(protocol_name)
                print(" ".join(parts))


if __name__ == "__main__":
    scan_ports()