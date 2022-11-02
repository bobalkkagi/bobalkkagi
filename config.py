class globar_var:
    a_queue=[]
    queue_size = 10


class DLL_SETTING:

    DLL_FUNCTIONS = {}
    LOADED_DLL = {} # {dll: address}
    INV_DLL_FUNCTIONS ={}
    INV_LOADED_DLL = {}

class HEAP_HANDLE:
    heap_handle=[0x000001E9E3850000]
    heap_handle_size=1

def i_queue(data):
    globar_var.a_queue.insert(0,data)
def p_queue():
    globar_var.a_queue.pop()
def get_queue():
    return globar_var.a_queue
def get_len():
    return len(globar_var.a_queue)
def get_size():
    return globar_var.queue_size

def InvDllDict():
    DLL_SETTING.INV_DLL_FUNCTIONS = {v: k for k, v in DLL_SETTING.DLL_FUNCTIONS.items()}
    DLL_SETTING.INV_LOADED_DLL = {v: k for k, v in DLL_SETTING.LOADED_DLL.items()}