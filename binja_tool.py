
from langchain.tools import tool
from typing import Optional
GLOBAL_BV = None
def set_bv(bv):
    global GLOBAL_BV
    GLOBAL_BV = bv

def lookup_function(identifier: str) -> Optional[str]:
    """
    Lookup a function by identifier.
    """
    print(f'Looking up function {identifier}')
    f = GLOBAL_BV.get_functions_by_name(identifier)
    if len(f) == 0:
        print(f'No function found for {identifier}')
        return None
    
    f = f[0]
    print(f'Found function {identifier}')
    return str(f.hlil)
