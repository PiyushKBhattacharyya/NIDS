from enum import Enum

class Action(Enum):
    """An action to be done by the NIDS in case of detected packet."""
    ALERT = 1
    DROP = 2  
    LOG = 3   
    PASS = 4  

def action(istr):
    """Return Action corresponding to the string."""
    action_str = istr.lower().strip()
    if action_str == "alert":
        return Action.ALERT
    else:
        raise ValueError("Invalid rule: incorrect action: '" + istr + "'.")
