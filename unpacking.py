from emulation import *
from globalValue import GLOBAL_VAR

def UnpackProgram(protectedFile, verbose):
    GLOBAL_VAR.ProtectedFile = protectedFile
    emulate(protectedFile, verbose)

