class globar_var:
    a_queue=[]
    queue_size = 10

class DLL_SETTING:
    INV_DLL_FUNCTIONS = {}
    DLL_FUNCTIONS = {v: k for k, v in INV_DLL_FUNCTIONS.items()}
    LOADED_DLL = {} # {dll: address}

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