import os
import sys
import signal
import logging
import argparse
from collections import defaultdict
from datetime import datetime

import warnings
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, conf, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IPv6

conf.verb = 0
conf.warning_threshold = 0
conf.logLevel = logging.ERROR


def setup_logger(log_file=None):
    fmt = "%(asctime)s  %(levelname)-7s  %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, mode="a"))
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt="%H:%M:%S", handlers=handlers)


logger = logging.getLogger("PacketAnalyzer")


class Stats:
    def __init__(self):
        self.total = 0
        self.by_proto = defaultdict(int)
        self.start_time = datetime.now()

    def record(self, proto):
        self.total += 1
        self.by_proto[proto] += 1

    def summary(self):
        elapsed = (datetime.now() - self.start_time).seconds
        lines = [
            "",
            "-" * 50,
            f"  Session summary  ({elapsed}s)",
            "-" * 50,
            f"  Total packets : {self.total}",
        ]
        for proto, count in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            bar = "#" * min(count, 30)
            lines.append(f"  {proto:<10} {count:>5}  {bar}")
        lines.append("-" * 50)
        return "\n".join(lines)


class PacketAnalyzer:
    TCP_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS/TCP", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    }

    UDP_SERVICES = {
        53: "DNS", 67: "DHCP-server", 68: "DHCP-client",
        123: "NTP", 161: "SNMP", 500: "IKE", 1900: "SSDP", 5353: "mDNS",
    }

    PROTO_NAMES = {
        1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
        47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
    }

    ICMP_TYPES = {
        0: "Echo Reply", 3: "Destination Unreachable",
        5: "Redirect", 8: "Echo Request", 11: "TTL Exceeded",
    }

    def __init__(self, interface, filter_exp=None, log_file=None, verbose=False):
        self.interface = interface
        self.filter_exp = filter_exp
        self.log_file = log_file
        self.verbose = verbose
        self.stats = Stats()
        self._sock = None
        self.running = False

    def start(self, count=0):
        logger.info(f"Interface  : {self.interface}")
        logger.info(f"Filter     : {self.filter_exp or 'none'}")
        logger.info(f"Limit      : {'unlimited' if count == 0 else count}")
        logger.info(f"Log file   : {self.log_file or 'disabled'}")
        logger.info("-" * 50)

        signal.signal(signal.SIGINT, self._on_stop)
        self.running = True

        try:
            self._sock = conf.L2socket(iface=self.interface)
            sniff(
                opened_socket=self._sock,
                filter=self.filter_exp,
                prn=self._handle,
                store=False,
                count=count,
                quiet=True,
            )
        except PermissionError:
            logger.error("Permission denied. Run with sudo.")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Cannot open '{self.interface}': {e}")
            sys.exit(1)
        except Exception as e:
            if self.running:
                logger.error(f"Error: {e}")
        finally:
            self._teardown()

    def _on_stop(self, sig, frame):
        self.running = False
        logger.info("Stopped.")
        self._teardown()
        print(self.stats.summary())
        sys.exit(0)

    def _teardown(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self.running = False

    def _ts(self, packet):
        try:
            return datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            return datetime.now().strftime("%H:%M:%S.000")

    def _handle(self, packet):
        try:
            if IP in packet:
                self._dissect(packet, packet[IP].src, packet[IP].dst, packet[IP].proto)
            elif IPv6 in packet:
                self._dissect(packet, packet[IPv6].src, packet[IPv6].dst, packet[IPv6].nh)
        except Exception:
            pass

    def _dissect(self, packet, src, dst, proto):
        ts = self._ts(packet)
        header = f"[{ts}]  {src:<18} -> {dst:<18}"

        if TCP in packet:
            self._tcp(packet, header)
        elif UDP in packet:
            self._udp(packet, header)
        elif ICMP in packet:
            label = self.ICMP_TYPES.get(packet[ICMP].type, f"type={packet[ICMP].type}")
            logger.info(f"{header}  ICMP  {label}")
            self.stats.record("ICMP")
        elif proto == 2:
            logger.info(f"{header}  IGMP")
            self.stats.record("IGMP")
        else:
            name = self.PROTO_NAMES.get(proto, f"proto-{proto}")
            if self.verbose and Raw in packet:
                snippet = bytes(packet[Raw])[:32].hex()
                logger.info(f"{header}  {name}  [{snippet}...]")
            else:
                logger.info(f"{header}  {name}")
            self.stats.record(name)

        if self.log_file:
            self._write_log(packet)

    def _tcp(self, packet, header):
        tcp = packet[TCP]
        sport, dport = tcp.sport, tcp.dport
        flags = self._flag_str(tcp.flags)
        size = len(tcp.payload)

        svc = self.TCP_SERVICES.get(dport) or self.TCP_SERVICES.get(sport, "")
        tag = f" [{svc}]" if svc else ""

        line = f"{header}  TCP  {sport} -> {dport}{tag}  flags={flags}  seq={tcp.seq}  len={size}"

        if dport == 80 or sport == 80:
            logger.info(f"{line}  | {self._http(packet)}")
            self.stats.record("HTTP")
        elif dport == 443 or sport == 443:
            logger.info(f"{line}  | TLS")
            self.stats.record("HTTPS")
        else:
            logger.info(line)
            self.stats.record("TCP")

    def _udp(self, packet, header):
        udp = packet[UDP]
        sport, dport = udp.sport, udp.dport
        size = len(udp.payload)

        svc = self.UDP_SERVICES.get(dport) or self.UDP_SERVICES.get(sport, "")
        tag = f" [{svc}]" if svc else ""

        line = f"{header}  UDP  {sport} -> {dport}{tag}  len={size}"

        if dport == 53 or sport == 53:
            logger.info(f"{line}  | {self._dns(packet)}")
            self.stats.record("DNS")
        elif dport in (5353, ) or sport == 5353:
            logger.info(f"{line}  | mDNS")
            self.stats.record("mDNS")
        elif dport in (67, 68):
            logger.info(f"{line}  | DHCP")
            self.stats.record("DHCP")
        elif dport == 123 or sport == 123:
            logger.info(f"{line}  | NTP")
            self.stats.record("NTP")
        else:
            logger.info(line)
            self.stats.record("UDP")

    def _http(self, packet):
        try:
            if packet.haslayer(HTTPRequest):
                req = packet[HTTPRequest]
                method = req.Method.decode(errors="replace")
                host = (req.Host or b"").decode(errors="replace") or "-"
                path = (req.Path or b"/").decode(errors="replace")
                ua = (req.User_Agent or b"").decode(errors="replace")
                ua = ua[:50] + "..." if len(ua) > 50 else ua
                out = f"HTTP {method} {host}{path}"
                if ua:
                    out += f"  ua={ua}"
                return out
            elif packet.haslayer(HTTPResponse):
                res = packet[HTTPResponse]
                code = (res.Status_Code or b"???").decode(errors="replace")
                reason = (res.Reason_Phrase or b"").decode(errors="replace")
                ctype = (res.Content_Type or b"").decode(errors="replace")
                out = f"HTTP {code} {reason}"
                if ctype:
                    out += f"  type={ctype}"
                return out
            return "HTTP data"
        except Exception:
            return "HTTP (error)"

    def _dns(self, packet):
        try:
            if DNS not in packet:
                return "DNS"
            dns = packet[DNS]
            if dns.qr == 0:
                qname = "-"
                if dns.qd and hasattr(dns.qd, "qname"):
                    qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                qtype = dns.qd.qtype if dns.qd else "?"
                return f"query {qname} type={qtype}"
            else:
                answers = []
                rr = dns.an
                while rr and rr != 0:
                    try:
                        answers.append(str(rr.rdata))
                    except Exception:
                        pass
                    rr = rr.payload if hasattr(rr, "payload") else None
                    if not hasattr(rr, "rdata"):
                        break
                return "response " + (", ".join(answers) if answers else "empty")
        except Exception:
            return "DNS (error)"

    @staticmethod
    def _flag_str(flags):
        bits = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
        active = [name for bit, name in bits.items() if int(flags) & bit]
        return " ".join(active) if active else str(flags)

    def _write_log(self, packet):
        try:
            with open(self.log_file, "a") as f:
                f.write(packet.summary() + "\n")
        except Exception:
            pass


def build_parser():
    parser = argparse.ArgumentParser(
        prog="packet_analyzer",
        description="Network packet capture and protocol dissection tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python3 main.py -i eth0
  sudo python3 main.py -i eth0 -f "tcp port 80" -c 200 -l out.log
  sudo python3 main.py -i wlan0 -f "udp port 53" -v
        """,
    )
    parser.add_argument("-i", "--interface", required=True, metavar="IFACE",
                        help="network interface (e.g. eth0, wlan0)")
    parser.add_argument("-f", "--filter", default=None, metavar="BPF",
                        help="BPF filter (e.g. 'tcp port 443')")
    parser.add_argument("-c", "--count", type=int, default=0, metavar="N",
                        help="stop after N packets (0 = unlimited)")
    parser.add_argument("-l", "--log", default=None, metavar="FILE",
                        help="write packet summaries to FILE")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show hex payload for unknown protocols")
    return parser


def main():
    sys.stderr = open(os.devnull, "w")

    args = build_parser().parse_args()
    setup_logger(log_file=args.log)

    analyzer = PacketAnalyzer(
        interface=args.interface,
        filter_exp=args.filter,
        log_file=args.log,
        verbose=args.verbose,
    )
    analyzer.start(count=args.count)


if __name__ == "__main__":
    main()