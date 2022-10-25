from emulation import *

#inv_map = {v: k for k, v in my_map.items()}


# Inv_DLL_FUNCTIONS = {v: k for k, v in DLL_FUNCTIONS.items()}

def UnpackProgram(protectedFile, verbose):
    emulate(protectedFile, verbose)

