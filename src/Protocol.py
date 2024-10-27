from enum import Enum

class Protocol(Enum):
    """A transport protocol or an application protocol concerning an IP packet."""
    TCP = 1
    UDP = 2
    HTTP = 3

def protocol(istr: str) -> Protocol:
    """Return the Protocol corresponding to the given string.

    Args:
        istr (str): The protocol name as a string (e.g., 'tcp', 'udp', 'http').

    Returns:
        Protocol: The corresponding Protocol enum value.

    Raises:
        ValueError: If the input string does not match any known protocols.
    """
    normalized_str = istr.lower().strip()
    
    if normalized_str == "tcp":
        return Protocol.TCP
    elif normalized_str == "udp":
        return Protocol.UDP
    elif normalized_str == "http":
        return Protocol.HTTP
    else:
        raise ValueError(f"Invalid rule: incorrect protocol: '{istr}'.")
