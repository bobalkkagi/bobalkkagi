import fire #type: ignore
from unpacking import *

def main() -> None:
    fire.Fire(run_Bobalkkagi)

def run_Bobalkkagi(
    protectedFile:str,
    verbose:bool = True
    ) -> None:
    if protectedFile is None:
        print("Bobalkkagi <.exe>")
    UnpackProgram(protectedFile, verbose)

