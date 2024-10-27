"""Functions for reading a file of rules."""

from Action import *
from Protocol import *
from IPNetwork import *
from Ports import *
from Rule import *

def read(filename: str) -> tuple[list[Rule], int]:
    """Read the input file for rules and return the list of rules and the number of line errors.

    Args:
        filename (str): The path to the file containing rules.

    Returns:
        tuple: A tuple containing a list of Rule objects and an integer count of line errors.
    """
    rules = []
    ruleErrorCount = 0
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            try:
                rule = Rule(line)
                rules.append(rule)
            except ValueError as err:
                ruleErrorCount += 1
                print(f"Error parsing rule: {err}")

    return rules, ruleErrorCount
