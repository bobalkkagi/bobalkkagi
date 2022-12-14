from unicorn import *
from unicorn.x86_const import *

from .loader import PE_Loader
from .reflector import REFLECTOR
from .globalValue import DLL_SETTING, HEAP_HANDLE, InvDllDict, GLOBAL_VAR
from .util import *

import struct
import os
import random


ThreadHandle=[]
AllocChunk = {}
Token=[]


privilege = {
        0x0: UC_PROT_EXEC | UC_PROT_READ, 
        0x2: UC_PROT_READ, 
        0x4: UC_PROT_READ | UC_PROT_WRITE,
        0x10:UC_PROT_EXEC,
        0x20:UC_PROT_EXEC | UC_PROT_READ, 
        0x40:UC_PROT_ALL
    }

class REGS:
    rax=None    
    rbx=None
    rcx=None
    rdx=None
    rdi=None
    rsi=None
    rsp=None
    rbp=None
    rip=None
    r8=None
    r9=None
    r10=None
    r11=None
    r12=None
    r13=None
    r14=None
    r15=None
    rflags=None

def set_register(register):
    
    REGS.rax=register["rax"]
    REGS.rbx=register["rbx"]
    REGS.rcx=register["rcx"]
    REGS.rdx=register["rdx"]
    REGS.rdi=register["rdi"]
    REGS.rsi=register["rsi"]
    REGS.rsp=register["rsp"]
    REGS.rbp=register["rbp"]
    REGS.rip=register["rip"]
    REGS.r8=register["r8"]
    REGS.r9=register["r9"]
    REGS.r10=register["r10"]
    REGS.r11=register["r11"]
    REGS.r12=register["r12"]
    REGS.r13=register["r13"]
    REGS.r14=register["r14"]
    REGS.r15=register["r15"]
    REGS.rflags=register["rflags"]

def ret(uc, rsp):
    
    ret=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
    uc.reg_write(UC_X86_REG_RIP, ret)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)
    

def hook_GetModuleFileNameW(uc, log, regs):
    
    set_register(regs)
    if not REGS.rcx:
        path = os.path.abspath(GLOBAL_VAR.ProtectedFile)
    else:
        try:
            module_name = DLL_SETTING.LoadedDll[REGS.rcx]
        except KeyError:
            module_name = "somefakename.dll"
        path = f"C:/Windows/System32/{module_name}"
    
    uc.reg_write(UC_X86_REG_R11,REGS.rdx)
    
    log.warning(f"HOOK_API_CALL : GetModuleFileNameW, RDX : {hex(REGS.rdx)}, path : {path}")
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rbp))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rdx,path.encode("utf-16"))
    uc.reg_write(UC_X86_REG_RAX,len(path))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    
    ret(uc, REGS.rsp)
    

def hook_GetModuleHandleA(uc, log, regs):
    
    set_register(regs)
    
    d_address = 0
    
    handle = EndOfString(bytes(uc.mem_read(REGS.rcx, 0x50))).lower()
     
    
    if handle in REFLECTOR:
        handle = REFLECTOR[handle]
    
    if handle in DLL_SETTING.LoadedDll:
        d_address = DLL_SETTING.LoadedDll[handle]

    log.warning(f"HOOK_API_CALL : GetModuleHandleA, Handle : {handle}, Address : {hex(d_address)}")   
    if d_address:
        uc.reg_write(UC_X86_REG_RAX, d_address)
    
    ret(uc, REGS.rsp)

def hook_LoadLibraryA(uc, log, regs):
    
    set_register(regs)

    d_address = 0
    dllName = EndOfString(bytes(uc.mem_read(REGS.rcx, 0x20))) #byte string
    
    if dllName not in DLL_SETTING.LoadedDll:
        PE_Loader(uc, dllName, GLOBAL_VAR.DllEnd)
        InvDllDict()

    d_address = DLL_SETTING.LoadedDll[dllName]
    if d_address:
        uc.reg_write(UC_X86_REG_RAX,d_address)
    else:
        print(f"[LOAD ERROR] {dllName}: {hex(d_address)}")


    log.warning(f"HOOK_API_CALL : LoadLibraryA, {dllName}: {hex(d_address)}")
    
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rsi))
    
    ret(uc, REGS.rsp)

def hook_GetProcAddress(uc, log, regs):
    
    set_register(regs)
  
    f_address = 0

    functionName=EndOfString(bytes(uc.mem_read(REGS.rdx, 0x20)))
    functionName = DLL_SETTING.InverseLoadedDll[REGS.rcx]+"_" + functionName
    f_address = DLL_SETTING.DllFuncs[functionName]

    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rbp))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',f_address))
    if f_address:
        uc.reg_write(UC_X86_REG_RAX,f_address)
    log.warning(f"HOOK_API_CALL : GetProcAddress, {functionName}: {hex(f_address)}")
    
    

    ret(uc, REGS.rsp)
    


def hook_ZwOpenThread(uc, log, regs):
    
    set_register(regs)
    
    handle = random.randrange(1,0x200)
    ThreadHandle.append(handle)
    uc.mem_write(REGS.rsp+0x90,struct.pack('<Q',handle))

    log.warning(f"HOOK_API_CALL : ZwOpenThread, handle : {hex(handle)}")    
    
    
    ret(uc, REGS.rsp)
    


def hook_GetUserDefaultUILanguage(uc, log, regs):
    
    set_register(regs)
    
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',0x409))
    log.warning(f"HOOK_API_CALL : GetUserDefaultUILanguage, RCX : {hex(REGS.rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x409)
    ret(uc, REGS.rsp)
    


def hook_RtlAllocateHeap(uc, log, regs):
    
    set_register(regs)

    HEAP_HANDLE.HeapHandle.append(HEAP_HANDLE.HeapHandle[HEAP_HANDLE.HeapHandleSize-1]+(align(REGS.r8)))
    HEAP_HANDLE.HeapHandleSize+=1

    uc.reg_write(UC_X86_REG_RAX,HEAP_HANDLE.HeapHandle[HEAP_HANDLE.HeapHandleSize-1])
   
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',0x3))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rdi))

    log.warning(f"HOOK_API_CALL : RtlAllocateHeap, handle : {hex(REGS.rcx)}, RAX : {hex(HEAP_HANDLE.HeapHandle[HEAP_HANDLE.HeapHandleSize-1])}")
    
    ret(uc, REGS.rsp)
    

def hook_GetCurrentDirectoryW(uc, log, regs):
    
    set_register(regs)
    
    cwd = os.getcwd()
    cwd_len = len(cwd)
    
    log.warning(f"HOOK_API_CALL : GetCurrentDirectoryW, RCX : {hex(REGS.rcx)}, RDX : {hex(REGS.rdx)}, path : {cwd}, len : {hex(cwd_len)}")
    
    uc.mem_write(REGS.rdx,cwd.encode('utf-8'))
    uc.reg_write(UC_X86_REG_RAX,cwd_len)
    uc.reg_write(UC_X86_REG_RCX,REGS.rdx)
    uc.reg_write(UC_X86_REG_R11,REGS.rdx)
    
    ret(uc, REGS.rsp)
    

def hook_SetCurrentDirectoryW(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : SetCurrentDirectoryW")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x1)
    ret(uc, REGS.rsp)
    

def hook_GetCommandLineA(uc, log, regs):
    
    set_register(regs)

    path = "\""+os.path.abspath(GLOBAL_VAR.ProtectedFile)+"\""
    
    log.warning(f"HOOK_API_CALL : GetCommandLineA, path : {path}")
    
    
    uc.mem_write(0x000001E9E3900000,path.encode("utf-8"))
    uc.reg_write(UC_X86_REG_RAX,0x000001E9E3900000) #임시포인터
    ret(uc, REGS.rsp)
    

def hook_ZwAllocateVirtualMemory(uc, log, regs):
    
    set_register(regs)

    REGS.rcx = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_RDX),8))[0]
    REGS.rdx = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_R9),8))[0]
    REGS.r9 = struct.unpack('<L',uc.mem_read(REGS.rsp+0x30,4))[0]
    
    page_size = 4 * 1024
    if REGS.rcx == 0:
        offset = GLOBAL_VAR.AllocateChunkEnd
    else:
        offset = REGS.rcx

    aligned_size = align(REGS.rdx, page_size)
    uc.mem_map(offset, aligned_size ,privilege[REGS.r9])
    GLOBAL_VAR.AllocateChunkEnd = offset + aligned_size
    AllocChunk[offset] = aligned_size
    log.warning(f"HOOK_API_CALL : ZwAllocateVirtualMemory, Address : {hex(offset)}, Size : {hex(REGS.rdx)}, Privilege : {hex(REGS.r9)}")
    uc.mem_write(uc.reg_read(UC_X86_REG_RDX),struct.pack('<Q',offset))
    uc.mem_write(uc.reg_read(UC_X86_REG_RDX)+0x8,struct.pack('<Q',aligned_size))

    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,REGS.rsp)
    uc.reg_write(UC_X86_REG_R9,REGS.rbp)
    ret(uc, REGS.rsp)
    



def hook_VirtualFree(uc, log, regs):
    
    set_register(regs)
    
   
    log.warning(f"HOOK_API_CALL : VirtualFree, Address : {hex(REGS.rcx)}")    
    uc.mem_unmap(REGS.rcx, AllocChunk[REGS.rcx])

    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q',AllocChunk[REGS.rcx]))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rcx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.rbx))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rsi))

    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    


def hook_OpenThreadToken(uc, log, regs):
    global Token
    set_register(regs)
    token = random.randrange(1,0x200)
    Token.append(token)
    log.warning(f"HOOK_API_CALL : OpenThreadToken")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    ret(uc, REGS.rsp)
    

def hook_OpenProcessToken(uc, log, regs):
    global Token
    set_register(regs)
    token = random.randrange(1, 0x200)
    Token.append(token)
    
    log.warning(f"HOOK_API_CALL : OpenProcessToken, token : {hex(token)}")
    uc.mem_write(REGS.r8,struct.pack('<Q',token))
    
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_ZwOpenThreadTokenEx(uc, log, regs):
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwOpenThreadTokenEx")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x00000000C000007C)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip + 0x14)
    ret(uc, REGS.rsp)
    

def hook_ZwOpenProcessTokenEx(uc, log, regs):
    global Token
    set_register(regs)
     # tmp=ret

    token = random.randrange(1,0x200)
    Token.append(token)
    
    log.warning(f"HOOK_API_CALL : ZwOpenProcessTokenEx, token : {hex(token)}")
    
    uc.mem_write(REGS.r9,struct.pack('<Q',token))
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip + 0x14)
    ret(uc, REGS.rsp)
    

def hook_ZwDuplicateToken(uc, log, regs):
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwDuplicateToken")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    ret(uc, REGS.rsp)
    

def hook_ZwQueryInformationToken(uc, log, regs):
    global Token
    set_register(regs)
    
    token = random.randrange(1,0x200)
    Token.append(token)
    log.warning(f"HOOK_API_CALL : ZwQueryInformationToken, token : {hex(token)}")
    uc.mem_write(REGS.r10,struct.pack('<Q',token))
    
   
    uc.reg_write(UC_X86_REG_RAX,0x23) # STATUS_BUFFER_TOO_SMALL
    ret(uc, REGS.rsp)
    

def hook_ZwClose(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwClose, handle : {hex(REGS.rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    
    ret(uc, REGS.rsp)
    

def hook_ZwAccessCheck(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwAccessCheck")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    
    ret(uc, REGS.rsp)
    


def hook_VirtualProtect(uc, log, regs):
    

    set_register(regs)
    REGS.r8 = uc.reg_read(UC_X86_REG_R8) & 0xffffffff

    
    
    log.warning(f"HOOK_API_CALL : VirtualProtect, Address : {hex(REGS.rcx)}, Size : {hex(REGS.rdx)}, Privilege : {hex(REGS.r8)}")
    
    if align(REGS.rcx) > REGS.rcx:   
        offset =  REGS.rcx - (align(REGS.rcx)- 0x1000)
        uc.mem_protect(align(REGS.rcx)-0x1000, align(REGS.rdx+offset), privilege[REGS.r8])   
    else:   
        uc.mem_protect(align(REGS.rcx), align(REGS.rdx), privilege[REGS.r8])
    
    oldPriv=0
    for section in GLOBAL_VAR.SectionInfo:
        if (REGS.rcx - section[1]) >= 0 and (REGS.rcx - section[1]) < section[2] :
            oldPriv = section[3]
            break         
    
    uc.mem_write(REGS.rsp+8, struct.pack('<Q',REGS.rdx))
    uc.mem_write(REGS.r9, struct.pack('<L',oldPriv))
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,REGS.rsp-0x50)
    uc.reg_write(UC_X86_REG_R9,REGS.r8)
    ret(uc, REGS.rsp)
    

def hook_NtUserGetForegroundWindow(uc, log, regs):
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : NtUserGetForegroundWindow")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rip+0x14)
    
    ret(uc, REGS.rsp)
    

def hook_GetWindowTextA(uc, log, regs):
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : GetWindowTextA")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.mem_write(REGS.rsp+0x8,struct.pack('<Q', REGS.rbx))
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q', REGS.rsi))
    ret(uc, REGS.rsp)
    


def hook_ZwRaiseException(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwRaiseException")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    
    ret(uc, REGS.rsp)
    
'''
'''
def hook_RtlRaiseStatus(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RtlRaiseStatus")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    
    ret(uc, REGS.rsp)
    



def hook_RtlFreeHeap(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : RtlFreeHeap, handle : {hex(REGS.rcx)},")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_ZwQueryInformationProcess(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwQueryInformationProcess")
    
    
    if REGS.rdx == 0x7:
        uc.mem_write(REGS.r8,struct.pack('<Q',0x0))
        uc.reg_write(UC_X86_REG_RAX, 0x0)
    elif REGS.rdx == 0x1e:
        uc.reg_write(UC_X86_REG_RAX, 0xC0000353)
        uc.mem_write(REGS.r8,struct.pack('<Q',0x0))
    elif REGS.rdx == 0x1f:
        uc.reg_write(UC_X86_REG_RAX, 0x1)
        uc.mem_write(REGS.r8,struct.pack('<Q',0x1))
    else:
        uc.reg_write(UC_X86_REG_RAX, 0x0)

    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rsi+0x14)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    
    ret(uc, REGS.rsp)
    


def hook_ZwQuerySystemInformation(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwQuerySystemInformation")
    
    

    #uc.reg_write(UC_X86_REG_RAX, 0xC0000023)
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)
    

def hook_ZwSetInformationThread(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : ZwSetInformationThread")
    
    
    if REGS.rdx == 0x11:
        uc.reg_write(UC_X86_REG_RDX, 0x0)

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    #uc.reg_write(UC_X86_REG_RCX, rax+0x14)
    #uc.reg_write(UC_X86_REG_R8, rsp)
    #uc.reg_write(UC_X86_REG_R9, rdi)
    
    ret(uc, REGS.rsp)
    

def hook_ZwSetInformationProcess(uc, log, regs):  # 안티디버깅
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwSetInformationProcess")
    
    
    if REGS.rdx == 0x11:
        uc.reg_write(UC_X86_REG_RDX, 0x0)

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, REGS.rax+0x14)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rdi)
    ret(uc, REGS.rsp)
    

def hook_RegOpenKeyExA(uc, log, regs): 
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : RegOpenKeyExA")
    
    text = EndOfString(bytes(uc.mem_read(REGS.rdx, 0x100)))
    if text == "HARDWARE\ACPI\DSDT\VBOX__":
        uc.reg_write(UC_X86_REG_RAX, 0x2)
    else:
        uc.reg_write(UC_X86_REG_RAX, 0x0)
    
    ret(uc, REGS.rsp)
    

def hook_RegQueryValueExA(uc, log, regs): 
    
    set_register(regs)
    
    log.warning(f"HOOK_API_CALL : RegQueryValueExA")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)
    

def hook_RegCloseKey(uc, log, regs): 
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : RegCloseKey")
    

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)
    


def hook_ZwGetContextThread(uc, log, regs): #안티디버깅
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : ZwGetContextThread")
    
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)
    

def hook_ZwOpenKeyEx(uc, log, regs): #안티디버깅
    
    set_register(regs)
    
    
    log.warning(f"HOOK_API_CALL : ZwOpenKeyEx")
    
    
    handle = random.randrange(1,0x200)

    uc.mem_write(REGS.rcx, struct.pack('<Q',handle))
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_R8, REGS.rsp)
    uc.reg_write(UC_X86_REG_R9, REGS.rbp)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    ret(uc, REGS.rsp)
    
def hook__set_fmode(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _set_fmode, mode: {hex(REGS.rcx)}")
    
    
    ret(uc, REGS.rsp)

def hook__crt_atexit(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _crt_atexit, func+address: {hex(REGS.rcx)}")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook__configure_narrow_argv(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _configure_narrow_argv ")
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    ret(uc, REGS.rsp)

def hook__configthreadlocale(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _configthreadlocale ")
    
    uc.reg_write(UC_X86_REG_RAX, REGS.rcx+2)
    ret(uc, REGS.rsp)

def hook__initialize_narrow_environment(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _initialize_narrow_environment ")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)

def hook__get_initial_narrow_environment(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _get_initial_narrow_environment ")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)
    

def hook__initterm(uc, log, regs):
    
    set_register(regs)
   
    log.warning(f"HOOK_API_CALL : _initterm, start : {hex(REGS.rcx)}, end : {hex(REGS.rdx)} ")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    ret(uc, REGS.rsp)
    
def hook__isatty(uc, log, regs):
    
    set_register(regs)
  
    log.warning(f"HOOK_API_CALL : _isatty")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook___stdio_common_vfprintf(uc, log, regs):
    
    set_register(regs)
    
    uc.reg_write(UC_X86_REG_R11,REGS.rdx)
    
    string = EndOfString(bytes(uc.mem_read(REGS.r8, 0x50)))
    log.warning(f"HOOK_API_CALL : __stdio_common_vfprintf")
    uc.mem_write(REGS.rsp+0x10,struct.pack('<Q',REGS.rcx))
    uc.mem_write(REGS.rsp+0x18,struct.pack('<Q',REGS.r8))
    uc.mem_write(REGS.rsp+0x20,struct.pack('<Q',REGS.rsi))
    uc.mem_write(REGS.rsp+0x28,struct.pack('<Q',REGS.rdx))
    uc.reg_write(UC_X86_REG_RAX,len(string))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    
    ret(uc, REGS.rsp)
    

def hook_MessageBoxExW(uc, log, regs):
    
    set_register(regs)
  
    text = bytes(uc.mem_read(REGS.rdx, 0x100)).decode('utf-16')
    title = bytes(uc.mem_read(REGS.r8, 0x10)).decode('utf-16')
    
    log.warning(f"HOOK_API_CALL : MessageBoxExW, hadnle : {hex(REGS.rcx)}, TEXT : {text}, TITLE : {title}")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_MessageBoxW(uc, log, regs):
    
    set_register(regs)
  
    text = bytes(uc.mem_read(REGS.rdx, 0x20)).decode('utf-16')
    title = bytes(uc.mem_read(REGS.r8, 0x10)).decode('utf-16')
    
    log.warning(f"HOOK_API_CALL : MessageBoxW, hadnle : {hex(REGS.rcx)}, TEXT : {text}, TITLE : {title}")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    ret(uc, REGS.rsp)
    

def hook_exit(uc, log, regs):
    
    set_register(regs)
    log.warning(f"HOOK_API_CALL : exit, Process Terminate.")

    return 1