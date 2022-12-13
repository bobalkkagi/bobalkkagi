from pathlib import Path

from .unpacking import unpack
from .globalValue import GLOBAL_VAR
from .unwrapping import unwrap
from .util import checkInput

#from unwrapping import unwrap
import fire #type: ignore
import sys


def main() -> None:
    fire.Fire(run_Bobalkkagi)

def run_Bobalkkagi(
    protectedFile:str,
    mode:str = 'f', #fast
    verbose:str = 'f',
    dllPath:str = "win10_v1903",
    oep:str = 't',
    debugger:str = 'f'
    ) -> None:

    filePath = Path(protectedFile)
    if not filePath.is_file():
        print(f"{filePath} isn't a file or doesn't exist")
        sys.exit(1)

    if mode in ['f', 'c', 'b']:
        pass
    else:
        print(f"{mode} isn't defined mode[f, c, b]")
        sys.exit(1)

    dllDirPath = Path(dllPath)
    if not dllDirPath.is_dir():
        print(f"{dllDirPath} isn't a directory or doesn't exist")
        sys.exit(1)
    

    verbose = checkInput(verbose)
    oep = checkInput(oep)
    debugger =checkInput(debugger)
    
    GLOBAL_VAR.DebugOption = debugger
    GLOBAL_VAR.ProtectedFile = protectedFile
    GLOBAL_VAR.DirectoryPath = dllPath

    dump, OrignalEntryPoint = unpack(protectedFile, verbose, mode, oep)
    unwrap(dump, OrignalEntryPoint)



