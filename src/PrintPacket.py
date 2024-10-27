import re
from scapy.all import *

from Utils import *
from Rule import *

RED = '\033[91m'
ENDC = '\033[0m'

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def displayIP(ip):
    """Display the IPv4 header."""
    print("[IP HEADER]")
    print(f"\t Version: {ip.version}")
    print(f"\t IHL: {ip.ihl * 4} bytes")
    print(f"\t ToS: {ip.tos}")
    print(f"\t Total Length: {ip.len}")
    print(f"\t Identification: {ip.id}")
    print(f"\t Flags: {ip.flags}")
    print(f"\t Fragment Offset: {ip.frag}")
    print(f"\t TTL: {ip.ttl}")
    print(f"\t Protocol: {ip.proto}")
    print(f"\t Header Checksum: {ip.chksum}")
    print(f"\t Source: {ip.src}")
    print(f"\t Destination: {ip.dst}")
    if ip.ihl > 5:
        print(f"\t Options: {ip.options}")

def displayMatchedIP(ip, rule):
    """Display the IPv4 header with matched fields in red."""
    print("[IP HEADER]")
    print(f"\t Version: {ip.version}")

    if hasattr(rule, "len"):
        print(RED + f"\t IHL: {ip.ihl * 4} bytes" + ENDC)
    else:
        print(f"\t IHL: {ip.ihl * 4} bytes")

    if hasattr(rule, "tos"):
        print(RED + f"\t ToS: {ip.tos}" + ENDC)
    else:
        print(f"\t ToS: {ip.tos}")

    print(f"\t Total Length: {ip.len}")
    print(f"\t Identification: {ip.id}")
    print(f"\t Flags: {ip.flags}")

    if hasattr(rule, "offset"):
        print(RED + f"\t Fragment Offset: {ip.frag}" + ENDC)
    else:
        print(f"\t Fragment Offset: {ip.frag}")

    print(f"\t TTL: {ip.ttl}")
    print(f"\t Protocol: {ip.proto}")
    print(f"\t Header Checksum: {ip.chksum}")

    if rule.srcIps.ipn.num_addresses == 1:
        print(RED + f"\t Source: {ip.src}" + ENDC)
    else:
        print(f"\t Source: {ip.src}")

    if rule.dstIps.ipn.num_addresses == 1:
        print(RED + f"\t Destination: {ip.dst}" + ENDC)
    else:
        print(f"\t Destination: {ip.dst}")

    if ip.ihl > 5:
        print(f"\t Options: {ip.options}")

def displayIPv6(ip):
    """Display the IPv6 header."""
    print("[IP HEADER]")
    print(f"\t Version: {ip.version}")
    print("\t Header Length: 40 bytes")
    print(f"\t Flow Label: {ip.fl}")
    print(f"\t Traffic Class: {ip.tc}")
    print(f"\t Source: {ip.src}")
    print(f"\t Destination: {ip.dst}")

# TCP
def displayTCP(tcp):
    """Display the TCP header."""
    print("[TCP Header]")
    print(f"\t Source Port: {tcp.sport}")
    print(f"\t Destination Port: {tcp.dport}")
    print(f"\t Sequence Number: {tcp.seq}")
    print(f"\t Acknowledgment Number: {tcp.ack}")
    print(f"\t Data Offset: {tcp.dataofs}")
    print(f"\t Reserved: {tcp.reserved}")
    print(f"\t Flags: {tcp.underlayer.sprintf('%TCP.flags%')}")
    print(f"\t Window Size: {tcp.window}")
    print(f"\t Checksum: {tcp.chksum}")

    if tcp.flags & URG:
        print(f"\t Urgent Pointer: {tcp.window}")
    if tcp.dataofs > 5:
        print(f"\t Options: {tcp.options}")

def displayMatchedTCP(tcp, rule):
    """Display the TCP header with matched fields in red."""
    print("[TCP Header]")
    if hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1:
        print(RED + f"\t Source Port: {tcp.sport}" + ENDC)
    else:
        print(f"\t Source Port: {tcp.sport}")

    if hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1:
        print(RED + f"\t Destination Port: {tcp.dport}" + ENDC)
    else:
        print(f"\t Destination Port: {tcp.dport}")

    if hasattr(rule, "seq"):
        print(RED + f"\t Sequence Number: {tcp.seq}" + ENDC)
    else:
        print(f"\t Sequence Number: {tcp.seq}")

    if hasattr(rule, "ack"):
        print(RED + f"\t Acknowledgment Number: {tcp.ack}" + ENDC)
    else:
        print(f"\t Acknowledgment Number: {tcp.ack}")

    print(f"\t Data Offset: {tcp.dataofs}")
    print(f"\t Reserved: {tcp.reserved}")

    if hasattr(rule, "flags"):
        print(RED + f"\t Flags: {tcp.underlayer.sprintf('%TCP.flags%')}" + ENDC)
    else:
        print(f"\t Flags: {tcp.underlayer.sprintf('%TCP.flags%')}")

    print(f"\t Window Size: {tcp.window}")
    print(f"\t Checksum: {tcp.chksum}")

    if tcp.flags & URG:
        print(f"\t Urgent Pointer: {tcp.window}")
    if tcp.dataofs > 5:
        print(f"\t Options: {tcp.options}")

# UDP
def displayUDP(udp):
    """Display the UDP header."""
    print("[UDP Header]")
    print(f"\t Source Port: {udp.sport}")
    print(f"\t Destination Port: {udp.dport}")
    print(f"\t Length: {udp.len}")
    print(f"\t Checksum: {udp.chksum}")

# Payload
def displayPayload(pkt):
    """Display the payload of the packet."""
    if pkt.payload:
        data = str(pkt.payload)
        lines = data.splitlines()
        for line in lines:
            print(f"\t{line}")

def displayMatchedTCPPayload(tcp, rule):
    """Display the TCP payload with matched content highlighted in red."""
    print("[TCP Payload]")
    if hasattr(rule, "http_request"):
        print(RED + f"HTTP Request: {rule.http_request}" + ENDC)

    if hasattr(rule, "content") and tcp.payload:
        data = str(tcp.payload)
        # Highlight matched content in red
        data = re.sub(rule.content, RED + rule.content + ENDC, data)
        lines = data.splitlines()
        for line in lines:
            print(f"\t{line}")
    else:
        displayPayload(tcp)

# Whole packet
def printMatchedPacket(pkt, rule):
    """Display the whole packet from IP to Application layer."""
    if IP in pkt:
        displayMatchedIP(pkt[IP], rule)
    elif IPv6 in pkt:
        displayIPv6(pkt[IPv6])
    
    if TCP in pkt:
        displayMatchedTCP(pkt[TCP], rule)
        displayMatchedTCPPayload(pkt[TCP], rule)
    
    elif UDP in pkt:
        displayUDP(pkt[UDP])
        print("[UDP Payload]")
        displayPayload(pkt[UDP])

def printPacket(pkt):
    """Display a packet from IP to Application layer."""
    if IP in pkt:
        displayIP(pkt[IP])
    elif IPv6 in pkt:
        displayIPv6(pkt[IPv6])
    
    if TCP in pkt:
        displayTCP(pkt[TCP])
        print("[TCP Payload]")
        displayPayload(pkt[TCP])
    
    elif UDP in pkt:
        displayUDP(pkt[UDP])
        print("[UDP Payload]")
        displayPayload(pkt[UDP])
