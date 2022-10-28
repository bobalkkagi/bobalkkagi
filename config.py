class globar_var:
    a_queue=[]
    queue_size = 10

class DLL_SETTING:

    DLL_FUNCTIONS = {} # {function : address}
    LOADED_DLL = {} # {dll : address}
    
    
    #def InvDict(self):
    #    self.INV_DLL_FUNCTIONS = {v: k for k, v in DLL_FUNCTIONS.items()}
    #    self.INV_LOADED_DLL = {v: k for k, v in LOADED_DLL.items()}

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
