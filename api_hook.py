from unicorn import *
from unicorn.x86_const import *
from loader import PE_Loader, REFLECTOR
from config import DLL_SETTING, HEAP_HANDLE, GLOBALVAR, InvDllDict, globar_var
from util import *
import logging
import struct
import os
import random


ALLOCATE_CHUNK_BASE=0x200000000
ALLOCATE_CHUNK_END=0x200000000
ThreadHandle=[]
AllocChunk = {}
Token=[]


def hook__set_fmode(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _set_fmode, mode: {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook__crt_atexit(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _crt_atexit, func+address: {hex(rcx)}")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook__configure_narrow_argv(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _configure_narrow_argv ")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook__configthreadlocale(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _configthreadlocale ")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX, rcx+2)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
def hook__initialize_narrow_environment(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _initialize_narrow_environment ")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook__get_initial_narrow_environment(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _get_initial_narrow_environment ")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook__initterm(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : _initterm, start : {hex(rcx)}, end : {hex(rdx)} ")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetModuleFileNameW(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    if not rcx:
        path = os.path.abspath(GLOBALVAR['PROTECTEDFILE'])
    else:
        try:
            module_name = DLL_SETTING.LOADED_DLL[rcx]
        except KeyError:
            module_name = "somefakename.dll"
        path = f"C:/Windows/System32/{module_name}"
    
   # log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_R11,rdx)
    
    #print(path.encode("utf-8"))
    #print(hex(len(path)))
    log.warning(f"HOOK_API_CALL : GetModuleFileNameW, RDX : {hex(rdx)}, path : {path}")
    uc.mem_write(rsp+0x8,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbp))
    uc.mem_write(rsp+0x18,struct.pack('<Q',rsi))
    uc.mem_write(rdx,path.encode("utf-16"))
    uc.reg_write(UC_X86_REG_RAX,len(path))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook__isatty(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
  
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
    
    log.warning(f"HOOK_API_CALL : _isatty")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook___stdio_common_vfprintf(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    
    
   # log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_R11,rdx)
    
    #print(path.encode("utf-8"))
    #print(hex(len(path)))
    string = EndOfString(bytes(uc.mem_read(r8, 0x50)))
    log.warning(f"HOOK_API_CALL : __stdio_common_vfprintf")
    uc.mem_write(rsp+0x10,struct.pack('<Q',rcx))
    uc.mem_write(rsp+0x18,struct.pack('<Q',r8))
    uc.mem_write(rsp+0x20,struct.pack('<Q',rsi))
    uc.mem_write(rsp+0x28,struct.pack('<Q',rdx))
    uc.reg_write(UC_X86_REG_RAX,len(string))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_MessageBoxExW(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
  
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    text = bytes(uc.mem_read(rdx, 0x100)).decode('utf-16')
    title = bytes(uc.mem_read(r8, 0x10)).decode('utf-16')
    
    
    log.warning(f"HOOK_API_CALL : MessageBoxExW, hadnle : {hex(rcx)}, TEXT : {text}, TITLE : {title}")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_MessageBoxW(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
  
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    text = bytes(uc.mem_read(rdx, 0x20)).decode('utf-16')
    title = bytes(uc.mem_read(r8, 0x10)).decode('utf-16')
    
    
    log.warning(f"HOOK_API_CALL : MessageBoxW, hadnle : {hex(rcx)}, TEXT : {text}, TITLE : {title}")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_exit(ip, rsp, uc, log):
    
    log.warning(f"HOOK_API_CALL : exit, Process Terminate.")
    #log.debug("DEBUGING")

    return 1

def hook_GetModuleHandleA(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    d_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    handle = EndOfString(bytes(uc.mem_read(rcx, 0x50))).lower()
    log.warning(f"HOOK_API_CALL : GetModuleHandleA, RCX : {handle}")    
    #log.debug("DEBUGING")
    if handle in REFLECTOR:
        handle = REFLECTOR[handle]
    
    if handle in DLL_SETTING.LOADED_DLL:
        d_address = DLL_SETTING.LOADED_DLL[handle]

    if d_address:
        uc.reg_write(UC_X86_REG_RAX, d_address)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP, tmp)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)

def hook_LoadLibraryA(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rip = uc.reg_read(UC_X86_REG_RIP)


    d_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    dllName = EndOfString(bytes(uc.mem_read(rcx, 0x20))) #byte string
    
    
    if dllName not in DLL_SETTING.LOADED_DLL:
        PE_Loader(uc, dllName, GLOBALVAR['NEXT_DLL_BASE'], None, os.path.abspath("vm_dll"))
        InvDllDict()

    d_address = DLL_SETTING.LOADED_DLL[dllName]
    if d_address:
        uc.reg_write(UC_X86_REG_RAX,d_address)
    else:
        print(f"[LOAD ERROR] {dllName}: {hex(d_address)}")


    log.warning(f"HOOK_API_CALL : LoadLibraryA, {dllName}: {hex(d_address)}")
    #log.debug("DEBUGING")
    uc.mem_write(rsp+0x8,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rsi))
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_GetProcAddress(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsi = uc.reg_read(UC_X86_REG_RSI)
  
    f_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    #func_nameByte = bytes(uc.mem_read(rdx, 0x20))
    
    
    functionName=EndOfString(bytes(uc.mem_read(rdx, 0x20)))
    functionName = DLL_SETTING.INV_LOADED_DLL[rcx]+"_" + functionName
    f_address = DLL_SETTING.DLL_FUNCTIONS[functionName]

    uc.mem_write(rsp+0x8,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x18,struct.pack('<Q',rbp))
    uc.mem_write(rsp+0x20,struct.pack('<Q',rsi))
    uc.mem_write(rsp+0x10,struct.pack('<Q',f_address))
    if f_address:
        uc.reg_write(UC_X86_REG_RAX,f_address)
    log.warning(f"HOOK_API_CALL : GetProcAddress, {functionName}: {hex(f_address)}")
    #log.debug("DEBUGING")
    

    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_ZwOpenThread(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    handle = random.randrange(1,0x200)
    ThreadHandle.append(handle)
    uc.mem_write(rsp+0x90,struct.pack('<Q',handle))

    log.warning(f"HOOK_API_CALL : ZwOpenThread, handle : {hex(handle)}")    
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_GetUserDefaultUILanguage(ip,rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
    uc.mem_write(rsp+0x8,struct.pack('<Q',0x409))
    log.warning(f"HOOK_API_CALL : GetUserDefaultUILanguage, RCX : {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x409)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_RtlAllocateHeap(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rdi = uc.reg_read(UC_X86_REG_RDI)

    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    HEAP_HANDLE.heap_handle.append(HEAP_HANDLE.heap_handle[HEAP_HANDLE.heap_handle_size-1]+(align(r8)))
    HEAP_HANDLE.heap_handle_size+=1

    uc.reg_write(UC_X86_REG_RAX,HEAP_HANDLE.heap_handle[HEAP_HANDLE.heap_handle_size-1])
   
    uc.mem_write(rsp+0x8,struct.pack('<Q',0x3))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x18,struct.pack('<Q',rsi))
    uc.mem_write(rsp+0x20,struct.pack('<Q',rdi))

    log.warning(f"HOOK_API_CALL : RtlAllocateHeap, handle : {hex(rcx)}, RAX : {hex(HEAP_HANDLE.heap_handle[HEAP_HANDLE.heap_handle_size-1])}")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetCurrentDirectoryW(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    rdx = uc.reg_read(UC_X86_REG_RDX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    cwd = os.getcwd()
    cwd_len = len(cwd)
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetCurrentDirectoryW, RCX : {hex(rcx)}, RDX : {hex(rdx)}, path : {cwd}, len : {hex(cwd_len)}")
    
    uc.mem_write(rdx,cwd.encode('utf-8'))
    uc.reg_write(UC_X86_REG_RAX,cwd_len)
    uc.reg_write(UC_X86_REG_RCX,rdx)
    uc.reg_write(UC_X86_REG_R11,rdx)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_SetCurrentDirectoryW(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    log.warning(f"HOOK_API_CALL : SetCurrentDirectoryW")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetCommandLineA(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    path = "\""+os.path.abspath(GLOBALVAR['PROTECTEDFILE'])+"\""
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetCommandLineA, path : {path}")
    
    #log.debug("DEBUGING")
    uc.mem_write(0x000001E9E3900000,path.encode("utf-8"))
    uc.reg_write(UC_X86_REG_RAX,0x000001E9E3900000) #임시포인터
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwAllocateVirtualMemory(ip, rsp, uc, log):
    global ALLOCATE_CHUNK_BASE
    global ALLOCATE_CHUNK_END
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    rcx = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_RDX),8))[0]
    rdx = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_R9),8))[0]
    r9 = struct.unpack('<L',uc.mem_read(rsp+0x30,4))[0]
    r8 = uc.reg_read(UC_X86_REG_R8)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    
    #log.debug("DEBUGING")
    
    privilege = {
        0x2: UC_PROT_READ, 
        0x4: UC_PROT_READ | UC_PROT_WRITE,
        0x10:UC_PROT_EXEC,
        0x20:UC_PROT_EXEC | UC_PROT_READ, 
        0x40:UC_PROT_ALL
    }
    
    
    page_size = 4 * 1024
    if rcx == 0:
        offset = ALLOCATE_CHUNK_END
    else:
        offset = rcx

    aligned_size = align(rdx, page_size)
    uc.mem_map(offset, aligned_size ,privilege[r9])
    ALLOCATE_CHUNK_END = offset + aligned_size
    AllocChunk[offset] = aligned_size
    log.warning(f"HOOK_API_CALL : ZwAllocateVirtualMemory, Address : {hex(offset)}, Size : {hex(rdx)}, Privilege : {hex(r9)}")
    uc.mem_write(uc.reg_read(UC_X86_REG_RDX),struct.pack('<Q',offset))
    uc.mem_write(uc.reg_read(UC_X86_REG_RDX)+0x8,struct.pack('<Q',aligned_size))

    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)



def hook_VirtualFree(ip, rsp, uc, log):
    global ALLOCATE_CHUNK_BASE
    global ALLOCATE_CHUNK_END
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    r9 = uc.reg_read(UC_X86_REG_R9)
    #log.debug("DEBUGING")
   
    
    log.warning(f"HOOK_API_CALL : VirtualFree, Address : {hex(rcx)}")    
    uc.mem_unmap(rcx, AllocChunk[rcx])

    uc.mem_write(rsp+0x8,struct.pack('<Q',AllocChunk[rcx]))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rcx))
    uc.mem_write(rsp+0x18,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x20,struct.pack('<Q',rsi))

    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_OpenThreadToken(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    token = random.randrange(1,0x200)
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : OpenThreadToken")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_OpenProcessToken(ip, rsp, uc, log):
    
    r8 = uc.reg_read(UC_X86_REG_R8)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    token = random.randrange(1,0x200)
    
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : OpenProcessToken, token : {hex(token)}")
    uc.mem_write(r8,struct.pack('<Q',token))
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwOpenThreadTokenEx(ip, rsp, uc, log):
    
    r8 = uc.reg_read(UC_X86_REG_R8)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

   
    
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwOpenThreadTokenEx")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x00000000C000007C)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_RCX,ip+0x14)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwOpenProcessTokenEx(ip, rsp, uc, log):
    
    r9 = uc.reg_read(UC_X86_REG_R9)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0] # tmp=ret

    token = random.randrange(1,0x200)
    
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwOpenProcessTokenEx, token : {hex(token)}")
    #log.debug("DEBUGING")
    uc.mem_write(r9,struct.pack('<Q',token))
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_R10,0x0)
    uc.reg_write(UC_X86_REG_RCX,ip+0x14)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwDuplicateToken(ip, rsp, uc, log):
    
    r8 = uc.reg_read(UC_X86_REG_R8)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

   
    
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwDuplicateToken")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_R10,0x0)
    uc.reg_write(UC_X86_REG_RCX,ip+0x14)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwQueryInformationToken(ip, rsp, uc, log):
    r10 = uc.reg_read(UC_X86_REG_R10)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    token = random.randrange(1,0x200)
    
    log.warning(f"HOOK_API_CALL : ZwQueryInformationToken, token : {hex(token)}")
    uc.mem_write(r10,struct.pack('<Q',token))
    #log.debug("DEBUGING")
   
    uc.reg_write(UC_X86_REG_RAX,0x23) # STATUS_BUFFER_TOO_SMALL
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwClose(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : ZwClose, handle : {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_R10,0x0)
    uc.reg_write(UC_X86_REG_RCX,ip+0x14)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwAccessCheck(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : ZwAccessCheck")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_R10,0x0)
    uc.reg_write(UC_X86_REG_RCX,ip+0x14)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_VirtualProtect(ip, rsp, uc, log):
    
    privilege = {
        0x0:UC_PROT_EXEC | UC_PROT_READ, 
        0x2: UC_PROT_READ, 
        0x4: UC_PROT_READ | UC_PROT_WRITE,
        0x10:UC_PROT_EXEC,
        0x20:UC_PROT_EXEC | UC_PROT_READ, 
        0x40:UC_PROT_ALL
    }
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8) & 0xffffffff
    r9 = uc.reg_read(UC_X86_REG_R9)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : VirtualProtect, Address : {hex(rcx)}, Size : {hex(rdx)}, Privilege : {hex(r8)}")
    if align(rcx) > rcx:	
        uc.mem_protect(align(rcx)-0x1000, align(rdx), privilege[r8])	
    else:	
        uc.mem_protect(align(rcx), align(rdx), privilege[r8])
    
    oldPriv=0
    for section in globar_var.SECTIONINFO:
        if (rcx - section[0]) >= 0 and (rcx - section[0]) < section[1] :
            oldPriv = section[2]
            break         
    #log.debug("DEBUGING")
    uc.mem_write(rsp+8, struct.pack('<Q',rdx))
    uc.mem_write(r9, struct.pack('<L',oldPriv))
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp-0x50)
    uc.reg_write(UC_X86_REG_R9,r8)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_NtUserGetForegroundWindow(ip, rsp, uc, log):
    rbp = uc.reg_read(UC_X86_REG_RBP)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : NtUserGetForegroundWindow")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_R8,rsp)
    uc.reg_write(UC_X86_REG_R9,rbp)
    uc.reg_write(UC_X86_REG_R10,0x0)
    uc.reg_write(UC_X86_REG_RCX,ip+0x14)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetWindowTextA(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetWindowTextA")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.mem_write(rsp+0x8,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rsi))
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_ZwRaiseException(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwRaiseException")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
'''
'''
def hook_RtlRaiseStatus(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : RtlRaiseStatus")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)



def hook_RtlFreeHeap(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : RtlFreeHeap")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwQueryInformationProcess(ip, rsp, uc, log):  # 안티디버깅
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    r8 = uc.reg_read(UC_X86_REG_R8)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : ZwQueryInformationProcess")
    #log.debug("DEBUGING")
    
    if rdx == 0x7:
        uc.mem_write(r8,struct.pack('<Q',0x0))
        uc.reg_write(UC_X86_REG_RAX, 0x0)
    elif rdx == 0x1e:
        uc.reg_write(UC_X86_REG_RAX, 0xC0000353)
        uc.mem_write(r8,struct.pack('<Q',0x0))
    elif rdx == 0x1f:
        uc.reg_write(UC_X86_REG_RAX, 0x1)
        uc.mem_write(r8,struct.pack('<Q',0x1))
    else:
        uc.reg_write(UC_X86_REG_RAX, 0x0)

    

    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, rsi+0x14)
    uc.reg_write(UC_X86_REG_R8, rsp)
    uc.reg_write(UC_X86_REG_R9, rbp)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_ZwQuerySystemInformation(ip, rsp, uc, log):  # 안티디버깅
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwQuerySystemInformation")
    #log.debug("DEBUGING")
    

    #uc.reg_write(UC_X86_REG_RAX, 0xC0000023)
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwSetInformationThread(ip, rsp, uc, log):  # 안티디버깅
    rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : ZwSetInformationThread")
    #log.debug("DEBUGING")
    
    if rdx == 0x11:
        uc.reg_write(UC_X86_REG_RDX, 0x0)

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    #uc.reg_write(UC_X86_REG_RCX, rax+0x14)
    #uc.reg_write(UC_X86_REG_R8, rsp)
    #uc.reg_write(UC_X86_REG_R9, rdi)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_ZwSetInformationProcess(ip, rsp, uc, log):  # 안티디버깅
    rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwSetInformationProcess")
    #log.debug("DEBUGING")
    
    if rdx == 0x11:
        uc.reg_write(UC_X86_REG_RDX, 0x0)

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, rax+0x14)
    uc.reg_write(UC_X86_REG_R8, rsp)
    uc.reg_write(UC_X86_REG_R9, rdi)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_RegOpenKeyExA(ip, rsp, uc, log): 
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : RegOpenKeyExA")
    #log.debug("DEBUGING")
    text = EndOfString(bytes(uc.mem_read(rdx, 0x100)))
    if text == "HARDWARE\ACPI\DSDT\VBOX__":
        uc.reg_write(UC_X86_REG_RAX, 0x2)
    else:
        uc.reg_write(UC_X86_REG_RAX, 0x0)
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_RegQueryValueExA(ip, rsp, uc, log): 
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : RegQueryValueExA")
    #log.debug("DEBUGING")
    

    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_RegCloseKey(ip, rsp, uc, log): 
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL :RegCloseKey")
    #log.debug("DEBUGING")

    dr0 = uc.reg_read(UC_X86_REG_DR0)
    dr1 = uc.reg_read(UC_X86_REG_DR1)
    dr2 = uc.reg_read(UC_X86_REG_DR2)
    dr3 = uc.reg_read(UC_X86_REG_DR3)
    dr4 = uc.reg_read(UC_X86_REG_DR4)
    dr5 = uc.reg_read(UC_X86_REG_DR5)
    dr6 = uc.reg_read(UC_X86_REG_DR6)
    dr7 = uc.reg_read(UC_X86_REG_DR7)
    dr8 = uc.reg_read(UC_X86_REG_DR8)
    dr9 = uc.reg_read(UC_X86_REG_DR9)
    dr10 = uc.reg_read(UC_X86_REG_DR10)
    dr11 = uc.reg_read(UC_X86_REG_DR11)
    
    uc.reg_write(UC_X86_REG_DR6, 0x0)
    uc.reg_write(UC_X86_REG_DR7, 0x0)
    
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)


def hook_ZwGetContextThread(ip, rsp, uc, log): #안티디버깅
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwGetContextThread")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_RIP, tmp)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)

def hook_ZwOpenKeyEx(ip, rsp, uc, log): #안티디버깅
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : ZwOpenKeyEx")
    #log.debug("DEBUGING")
    
    handle = random.randrange(1,0x200)

    uc.mem_write(rcx, struct.pack('<Q',handle))
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.reg_write(UC_X86_REG_R8, rsp)
    uc.reg_write(UC_X86_REG_R9, rbp)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_RIP, tmp)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)
