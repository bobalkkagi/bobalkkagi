from emulation import emulate
from globalValue import GLOBAL_VAR
from pathlib import Path
#from unwrapping import unwrap

import fire #type: ignore

def main() -> None:
    fire.Fire(run_Bobalkkagi)

def run_Bobalkkagi(
    protectedFile:str,
    mode:str = 'f', #fast
    verbose:bool = False,
    oep:bool = True,
    debugger:bool = False
    ) -> None:

    filePath = Path(protectedFile)
    if not filePath.is_file():
        print("Bobalkkagi <file>")
        exit()

    GLOBAL_VAR.DebugOption = debugger
    GLOBAL_VAR.ProtectedFile = protectedFile

    dumps, oepOffset = emulate(protectedFile, verbose, mode, oep)
    
    #unwrap(dumps, oepOffset)
