from ipaddress import ip_address
from scapy.all import *

from Utils import *
from Action import *
from Protocol import *
from IPNetwork import *
from Ports import *
from PacketStrings import *

class Rule:
    """A NIDS rule."""

    def __init__(self, rule_string: str):
        """Construct a rule from a string.

        Args:
            rule_string (str): The rule string to parse.

        Raises:
            ValueError: If the rule string is invalid.
        """
        self.string = rule_string.strip()
        parts = self.string.split(' ')

        if len(parts) < 7:
            raise ValueError(
                "Invalid rule: a rule must include mandatory elements: action protocol src_ips src_ports -> dst_ips dst_ports"
            )

        try:
            self.action = action(parts[0])
            self.protocol = protocol(parts[1])
            self.srcIps = IPNetwork(parts[2])
            self.srcPorts = Ports(parts[3])
            self.dstIps = IPNetwork(parts[5])
            self.dstPorts = Ports(parts[6])
        except ValueError as e:
            raise ValueError(f"Invalid rule: {str(e)}")

        options_part = self.string.split('(')
        if len(options_part) >= 2:
            self.parse_options(options_part[1])

    def __repr__(self):
        """Returns the string representing the Rule."""
        return self.string

    def parse_options(self, options_string: str):
        """Parse and set options from the options string.

        Args:
            options_string (str): The options portion of the rule string.
        """
        options_string = options_string.rstrip(')')
        options = options_string.split(';')

        for opt in options:
            kv = opt.split(':', 1)
            if len(kv) >= 2:
                option = kv[0].strip()
                value = kv[1].strip()
                self.set_option(option, value)
            else:
                raise ValueError(f"Invalid rule: incorrect option: '{opt}'.")

    def set_option(self, option: str, value: str):
        """Set the specific option based on the key-value pair.

        Args:
            option (str): The option name.
            value (str): The option value.
        """
        try:
            if option == "msg":
                self.msg = value
            elif option in ["tos", "len", "offset", "seq", "ack"]:
                setattr(self, option, int(value))
            elif option == "flags":
                self.flags = value
            elif option == "http_request":
                self.http_request = value.strip('"')
            elif option == "content":
                self.content = value.strip('"')
            else:
                raise ValueError(f"Invalid rule: incorrect option: '{option}'.")
        except ValueError:
            raise ValueError(f"Invalid value for option '{option}': '{value}'.")

    def match(self, pkt) -> bool:
        """Returns True if the rule matches the given packet.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if the packet matches the rule, False otherwise.
        """
        return (
            self.checkProtocol(pkt) and
            self.checkIps(pkt) and
            self.checkPorts(pkt) and
            self.checkOptions(pkt)
        )

    def checkProtocol(self, pkt) -> bool:
        """Returns True if the rule concerns the packet's protocol.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if the protocol matches, False otherwise.
        """
        if self.protocol == Protocol.TCP and TCP in pkt:
            return True
        elif self.protocol == Protocol.UDP and UDP in pkt:
            return True
        elif self.protocol == Protocol.HTTP and TCP in pkt and isHTTP(pkt):
            return True
        return False

    def checkIps(self, pkt) -> bool:
        """Returns True if the rule's IPs concern the packet's IPs.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if the IPs match, False otherwise.
        """
        if IP not in pkt:
            return False

        srcIp = ip_address(pkt[IP].src)
        dstIp = ip_address(pkt[IP].dst)
        return self.srcIps.contains(srcIp) and self.dstIps.contains(dstIp)

    def checkPorts(self, pkt) -> bool:
        """Returns True if the rule's ports concern the packet's ports.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if the ports match, False otherwise.
        """
        if UDP in pkt:
            srcPort = pkt[UDP].sport
            dstPort = pkt[UDP].dport
        elif TCP in pkt:
            srcPort = pkt[TCP].sport
            dstPort = pkt[TCP].dport
        else:
            return False

        return self.srcPorts.contains(srcPort) and self.dstPorts.contains(dstPort)

    def checkOptions(self, pkt) -> bool:
        """Return True if all options are matched.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if all options match, False otherwise.
        """
        option_checks = {
            "tos": lambda: self.tos == int(pkt[IP].tos) if IP in pkt else False,
            "len": lambda: self.len == int(pkt[IP].ihl) if IP in pkt else False,
            "offset": lambda: self.offset == int(pkt[IP].frag) if IP in pkt else False,
            "seq": lambda: self.seq == int(pkt[TCP].seq) if TCP in pkt else False,
            "ack": lambda: self.ack == int(pkt[TCP].ack) if TCP in pkt else False,
            "flags": lambda: all(c in pkt[TCP].underlayer.sprintf("%TCP.flags%") for c in self.flags) if TCP in pkt else False,
            "http_request": lambda: self.check_http_request(pkt),
            "content": lambda: self.check_content(pkt)
        }

        for option, check in option_checks.items():
            if hasattr(self, option) and not check():
                return False

        return True

    def check_http_request(self, pkt) -> bool:
        """Check if the HTTP request matches.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if the HTTP request matches, False otherwise.
        """
        if not isHTTP(pkt) or TCP not in pkt or not pkt[TCP].payload:
            return False

        data = str(pkt[TCP].payload)
        words = data.split(' ')
        return len(words) > 0 and words[0].rstrip() == self.http_request

    def check_content(self, pkt) -> bool:
        """Check if the content matches.

        Args:
            pkt: The packet to evaluate.

        Returns:
            bool: True if the content matches, False otherwise.
        """
        payload = pkt[TCP].payload if TCP in pkt else pkt[UDP].payload if UDP in pkt else None
        return payload is not None and self.content in str(payload)

    def getMatchedMessage(self, pkt) -> str:
        """Return the message to be logged when the packet triggered the rule.

        Args:
            pkt: The packet that triggered the rule.

        Returns:
            str: The log message.
        """
        msg = " ALERT " if self.action == Action.ALERT else ""
        if hasattr(self, "msg"):
            msg += self.msg + "\n"

        msg += f"Rule matched:\n{self}\nBy packet:\n{packetString(pkt)}\n"
        return msg

    def getMatchedPrintMessage(self, pkt) -> str:
        """Return the message to be printed in the console when the packet triggered the rule.

        Args:
            pkt: The packet that triggered the rule.

        Returns:
            str: The print message.
        """
        msg = RED + "ALERT " if self.action == Action.ALERT else ""
        if hasattr(self, "msg"):
            msg += self.msg
        msg += "\n" + ENDC

        msg += f"Rule matched:\n{self}\nBy packet:\n{matchedPacketString(pkt, self)}\n"
        return msg
