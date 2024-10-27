import re
from scapy.all import *
from Utils import *
from Rule import *

class TerminalColors:
    RED = '\033[91m'
    ENDC = '\033[0m'

def format_header(header_dict):
    """Construct a human-readable string from a header dictionary."""
    return "\n".join([f"\t {key}: {value}" for key, value in header_dict.items() if value is not None])

def print_ip_header(ip):
    """Construct the human-readable string corresponding to the IP header."""
    header_info = {
        "Version": ip.version,
        "IHL": f"{ip.ihl * 4} bytes",
        "ToS": ip.tos,
        "Total Length": ip.len,
        "Identification": ip.id,
        "Flags": ip.flags,
        "Fragment Offset": ip.frag,
        "TTL": ip.ttl,
        "Protocol": ip.proto,
        "Header Checksum": ip.chksum,
        "Source": ip.src,
        "Destination": ip.dst,
        "Options": str(ip.options) if ip.ihl > 5 else None,
    }
    return "[IP HEADER]\n" + format_header(header_info)

def print_matched_ip_header(ip, rule):
    """Print the matched IP header with matched fields highlighted."""
    header_info = {
        "Version": ip.version,
        "IHL": (TerminalColors.RED + f"{ip.ihl * 4} bytes" + TerminalColors.ENDC) if hasattr(rule, "len") else f"{ip.ihl * 4} bytes",
        "ToS": (TerminalColors.RED + str(ip.tos) + TerminalColors.ENDC) if hasattr(rule, "tos") else str(ip.tos),
        "Total Length": ip.len,
        "Identification": ip.id,
        "Flags": ip.flags,
        "Fragment Offset": (TerminalColors.RED + str(ip.frag) + TerminalColors.ENDC) if hasattr(rule, "offset") else str(ip.frag),
        "TTL": ip.ttl,
        "Protocol": ip.proto,
        "Header Checksum": ip.chksum,
        "Source": (TerminalColors.RED + str(ip.src) + TerminalColors.ENDC) if rule.srcIps.ipn.num_addresses == 1 else str(ip.src),
        "Destination": (TerminalColors.RED + str(ip.dst) + TerminalColors.ENDC) if rule.dstIps.ipn.num_addresses == 1 else str(ip.dst),
        "Options": str(ip.options) if ip.ihl > 5 else None,
    }
    return "[IP HEADER]\n" + format_header(header_info)

def print_tcp_header(tcp):
    """Construct the human-readable string corresponding to the TCP header."""
    header_info = {
        "Source Port": tcp.sport,
        "Destination Port": tcp.dport,
        "Sequence Number": tcp.seq,
        "Acknowledgment Number": tcp.ack,
        "Data Offset": tcp.dataofs,
        "Reserved": tcp.reserved,
        "Flags": tcp.underlayer.sprintf("%TCP.flags%"),
        "Window Size": tcp.window,
        "Checksum": tcp.chksum,
        "Urgent Pointer": tcp.urgptr if tcp.flags & URG else None,
        "Options": str(tcp.options) if tcp.dataofs > 5 else None,
    }
    return "[TCP HEADER]\n" + format_header(header_info)

def print_matched_tcp_header(tcp, rule):
    """Print the matched TCP header with matched fields highlighted."""
    header_info = {
        "Source Port": (TerminalColors.RED + str(tcp.sport) + TerminalColors.ENDC) if hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1 else str(tcp.sport),
        "Destination Port": (TerminalColors.RED + str(tcp.dport) + TerminalColors.ENDC) if hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1 else str(tcp.dport),
        "Sequence Number": (TerminalColors.RED + str(tcp.seq) + TerminalColors.ENDC) if hasattr(rule, "seq") else str(tcp.seq),
        "Acknowledgment Number": (TerminalColors.RED + str(tcp.ack) + TerminalColors.ENDC) if hasattr(rule, "ack") else str(tcp.ack),
        "Data Offset": tcp.dataofs,
        "Reserved": tcp.reserved,
        "Flags": (TerminalColors.RED + tcp.underlayer.sprintf("%TCP.flags%") + TerminalColors.ENDC) if hasattr(rule, "flags") else tcp.underlayer.sprintf("%TCP.flags%"),
        "Window Size": tcp.window,
        "Checksum": tcp.chksum,
        "Urgent Pointer": tcp.urgptr if tcp.flags & URG else None,
        "Options": str(tcp.options) if tcp.dataofs > 5 else None,
    }
    return "[TCP HEADER]\n" + format_header(header_info)

def print_udp_header(udp):
    """Construct the human-readable string corresponding to the UDP header."""
    header_info = {
        "Source Port": udp.sport,
        "Destination Port": udp.dport,
        "Length": udp.len,
        "Checksum": udp.chksum,
    }
    return "[UDP HEADER]\n" + format_header(header_info)

def print_matched_udp_header(udp, rule):
    """Print the matched UDP header with matched fields highlighted."""
    header_info = {
        "Source Port": (TerminalColors.RED + str(udp.sport) + TerminalColors.ENDC) if hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1 else str(udp.sport),
        "Destination Port": (TerminalColors.RED + str(udp.dport) + TerminalColors.ENDC) if hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1 else str(udp.dport),
        "Length": udp.len,
        "Checksum": udp.chksum,
    }
    return "[UDP HEADER]\n" + format_header(header_info)

def print_payload(pkt):
    """Construct a human-readable string corresponding to the payload."""
    if pkt.payload:
        data = str(pkt.payload)
        return "\n".join(f"\t{line}" for line in data.splitlines())
    return ""

def print_matched_tcp_payload(tcp, rule):
    """Print the TCP payload with matched fields highlighted."""
    out = "[TCP Payload]\n"
    if hasattr(rule, "http_request"):
        out += TerminalColors.RED + "HTTP Request: " + str(rule.http_request) + TerminalColors.ENDC + "\n"
    if hasattr(rule, "content") and tcp.payload:
        data = str(tcp.payload)
        data = re.sub(re.escape(rule.content), TerminalColors.RED + rule.content + TerminalColors.ENDC, data)
        out += print_payload(data)
    else:
        out += print_payload(tcp)
    return out

def print_matched_udp_payload(udp, rule):
    """Print the UDP payload with matched fields highlighted."""
    out = "[UDP Payload]\n"
    if hasattr(rule, "content") and udp.payload:
        data = str(udp.payload)
        data = re.sub(re.escape(rule.content), TerminalColors.RED + rule.content + TerminalColors.ENDC, data)
        out += print_payload(data)
    else:
        out += print_payload(udp)
    return out

