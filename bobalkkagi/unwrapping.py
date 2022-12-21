from datetime import datetime

from .util_unwrap import unwrapping

def unwrap(dumps, OEP:int):
    start = datetime.now()
    print(f"\033[93m[{start}] Unwrapping Start...\033[0m")
    unwrapping(dumps, OEP)
    end = datetime.now()
    print(f"\033[93m[{end}] Unwrapping End...\033[0m")
    print(f"\033[93mUnwrapping Runtime: [{end-start}]\033[0m")