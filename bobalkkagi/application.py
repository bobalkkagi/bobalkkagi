from pathlib import Path

from .emulation import emulate
from .globalValue import GLOBAL_VAR

#from unwrapping import unwrap
import fire #type: ignore
import sys

TFdict= {'T':True, 'F':False}

def main() -> None:
    fire.Fire(run_Bobalkkagi)

def run_Bobalkkagi(
    protectedFile:str,
    mode:str = 'f', #fast
    verbose = False,
    dllPath:str = "win10_v1903",
    oep:bool = True,
    debugger:bool = False
    ) -> None:

    filePath = Path(protectedFile)
    if not filePath.is_file():
        print(f"{filePath} isn't a file or doesn't exist")
        sys.exit(1)

    if mode not in ['f', 'c', 'b']:
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
    dumps, oepOffset = emulate(protectedFile, verbose, mode, oep)
    
    #unwrap(dumps, oepOffset)

def checkInput(userInput):
    if userInput not in ['T', 'F', True, False]:
        print("verbose isn't in [T/F, True/False]")
        sys.exit(1)

    if userInput in TFdict:
        userInput = TFdict[userInput]

    return userInput