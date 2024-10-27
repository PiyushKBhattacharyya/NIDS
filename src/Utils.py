from scapy.all import TCP, Packet  
HTTP_COMMANDS = {"GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"}

def isHTTP(pkt: Packet) -> bool:
    """Check if the given packet is an HTTP packet."""
    if TCP in pkt and pkt[TCP].payload:
        data = str(pkt[TCP].payload).strip()

        if "HTTP/" in data:
            return True

        words = data.split(' ')
        if words and words[0] in HTTP_COMMANDS:
            return True
        
    return False
