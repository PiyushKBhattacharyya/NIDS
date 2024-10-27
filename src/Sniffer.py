from threading import Thread
from scapy.all import *
import logging
import os
from datetime import datetime

import RuleFileReader
from Rule import *

log_dir = "Logs"
os.makedirs(log_dir, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = os.path.join(log_dir, f"NIDS_{timestamp}.log")

logging.basicConfig(filename=log_filename, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packets."""

    def __init__(self, ruleList: list):
        super().__init__()
        self.stopped = False
        self.ruleList = ruleList

    def stop(self):
        """Stop the packet sniffing."""
        self.stopped = True

    def stopfilter(self, x):
        """Stop filtering based on the stopped status."""
        return self.stopped

    def inPacket(self, pkt: Packet):
        """Directive for each received packet."""
        logging.info(f"Packet captured: {pkt.summary()}")
        try:
            for rule in self.ruleList:
                matched = rule.match(pkt)
                if matched:
                    logMessage = rule.getMatchedMessage(pkt)
                    logging.warning(logMessage)
                    print(rule.getMatchedPrintMessage(pkt))
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def run(self):
        """Start sniffing packets."""
        print("Sniffing started.")
        sniff(prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter)
