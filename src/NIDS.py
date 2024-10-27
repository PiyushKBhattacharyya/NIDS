from scapy.all import *
from sys import argv
import logging
from datetime import datetime

import RuleFileReader
from Sniffer import *

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename):
    """Read the rule file and start listening."""

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    logging.basicConfig(filename="Simple-NIDS_" + str(now) + '.log', level=logging.INFO)

    print("NIDS started.")
    print("Reading rule file...")
    global ruleList
    ruleList, errorCount = RuleFileReader.read(filename)
    print("Finished reading rule file.")

    if errorCount == 0:
        print(f"All ({len(ruleList)}) rules have been correctly read.")
    else:
        print(f"{len(ruleList)} rules have been correctly read.")
        print(f"{errorCount} rules have errors and could not be read.")

    sniffer = Sniffer(ruleList)
    sniffer.start()

    try:

        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping NIDS...")
        sniffer.stop() 
        sniffer.join() 
        print("NIDS stopped.")
ruleList = list()
script, filename = argv
main(filename)
