class Ports:
    """A TCP/UDP port set: a list, a range, or 'any'."""

    def __init__(self, string):
        """
        Construct a Ports object from a string that can be:
        - 'any': meaning the set contains any port
        - 'a:b': a range of ports from a to b
        - 'a,b,c...': a comma-separated list of specific ports
        """
        try:
            if string == "any":
                self.type = "any"
            elif ":" in string:
                self.type = "range"
                low, high = string.split(":")
                self.lowPort = int(low) if low else -1
                self.highPort = int(high) if high else -1
            elif "," in string:
                
                self.type = "list"
                self.listPorts = [int(port) for port in string.split(",")]
            else:
                
                self.type = "list"
                self.listPorts = [int(string)]
        except ValueError:
            raise ValueError("Incorrect input string.")

    def contains(self, port):
        """
        Check if a given port is in the set described by this Ports object.
        Returns True if the port is within the set, False otherwise.
        """
        if self.type == "any":
            return True
        elif self.type == "range":
  
            if self.lowPort == -1:
                return port <= self.highPort
            elif self.highPort == -1:
                return port >= self.lowPort
            else:
                return self.lowPort <= port <= self.highPort
        elif self.type == "list":
            return port in self.listPorts

    def __repr__(self):
        """
        String representation of the Ports object.
        Returns 'any', 'a:b', or a comma-separated list 'a,b,c...'.
        """
        if self.type == "any":
            return "any"
        elif self.type == "range":
            if self.lowPort == -1:
                return f":{self.highPort}"
            elif self.highPort == -1:
                return f"{self.lowPort}:"
            else:
                return f"{self.lowPort}:{self.highPort}"
        elif self.type == "list":
            return ",".join(map(str, self.listPorts))
