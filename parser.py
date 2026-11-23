import sys
import argparse
import ipaddress


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("-j", "--num-threads", type=int, default=10)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-g", "--guess", action="store_true")
    parser.add_argument("ip_address")
    parser.add_argument("targets", nargs="*")
    args = parser.parse_args()
    try:
        ipaddress.IPv4Address(args.ip_address)
    except ValueError:
        sys.stderr.write(f"Invalid IP address: {args.ip_address}\n")
        sys.exit(1)

    if not (args.timeout > 0):
        sys.stderr.write(f"Invalid timeout: {args.timeout}\n")
        sys.exit(1)
    if not (args.num_threads > 0):
        sys.stderr.write(f"Invalid number of threads: {args.num_threads}\n")
        sys.exit(1)

    return args

def parse_ports(targets):
    ports_number = 2 ** 16
    ports = {"tcp": set(),
             "udp": set()}
    if not targets:
        ports["tcp"].update(range(1, ports_number))
        ports["udp"].update(range(1, ports_number))
    else:
        for target in targets:
            if '/' in target:
                parts = target.split('/')
                if len(parts) > 2:
                    sys.stderr.write(f"Invalid target: {target}\n")
                    sys.exit(1)

                port_type = parts[0]
                target_ports = parts[1]
            else:
                port_type = target
                target_ports = f"1-{ports_number - 1}"

            port_type = port_type.lower()
            if port_type not in ("tcp", "udp"):
                sys.stderr.write(f"Invalid port type: {port_type}\n")
                sys.exit(1)

            target_ports = target_ports.split(',')
            for ports_range in target_ports:
                try:
                    if '-' in ports_range:
                        start, end = ports_range.split('-')
                    else:
                        start = ports_range
                        end = ports_range

                    start = int(start)
                    end = int(end)
                except ValueError:
                    sys.stderr.write(f"Invalid port range: {ports_range}\n")
                    sys.exit(1)

                if not 1 <= start <= end <= ports_number - 1:
                    sys.stderr.write(f"Invalid port range: {ports_range}\n")
                    sys.exit(1)

                ports[port_type].update(range(start, end + 1))

    return ports