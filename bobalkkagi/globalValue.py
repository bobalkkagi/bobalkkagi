from .hookFuncs import HookFuncs

class GLOBAL_VAR:
    ImageBaseStart = 0x140000000
    ImageBaseEnd = 0x140000000
    DllStart = 0x7FF000000000
    DllEnd = 0x7FF000000000
    AllocateChunkStart=0x0000020000000000
    AllocateChunkEnd=0x0000020000000000
    HookRegion=0x7FF010000000
    FindOEP = True
    DebugOption = False
    DebugFlag = False
    BreakPoint = []
    HookInt=0
    SectionInfo=[]
    InverseHookFuncs={}
    ProtectedFile = None
    DirectoryPath = None
    a_queue=[]
    queue_size = 20
    text = []



class DLL_SETTING:
    DllFuncs = {}
    LoadedDll = {} # {dll: address}
    InverseDllFuncs ={}
    InverseLoadedDll = {}
    

class HEAP_HANDLE:
    HeapHandle=[0x000001E9E3850000]
    HeapHandleSize=1

def i_queue(data):
    GLOBAL_VAR.a_queue.insert(0,data)
def p_queue():
    GLOBAL_VAR.a_queue.pop()
def get_queue():
    return GLOBAL_VAR.a_queue
def get_len():
    return len(GLOBAL_VAR.a_queue)
def get_size():
    return GLOBAL_VAR.queue_size

def InvDllDict():
    DLL_SETTING.InverseDllFuncs = {v: k for k, v in DLL_SETTING.DllFuncs.items()}
    DLL_SETTING.InverseLoadedDll = {v: k for k, v in DLL_SETTING.LoadedDll.items()}
   
def InvHookFuncDict():
    GLOBAL_VAR.InverseHookFuncs = {v: k for k, v in HookFuncs.items()}

