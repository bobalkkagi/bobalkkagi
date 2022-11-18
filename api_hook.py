from unicorn import *
from unicorn.x86_const import *
from loader import EndOfString, PE_Loader
from config import DLL_SETTING, HEAP_HANDLE, GLOBALVAR

import logging
import struct
import os
import random

ALLOCATE_CHUNK_BASE=0x2000000
ALLOCATE_CHUNK_END=0x2000000
ThreadHandle=[]
AllocChunk = {}


def align(value, page_size=4096):
    m = value % page_size
    f = page_size - m
    aligned_size = value + f
    return aligned_size

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

def hook_ZwQueryVirtualMemory(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    log.warning(f"HOOK_API_CALL : ZwQueryVirtualMemory, handle : {hex(rcx)} ")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX, 0)
    uc.mem_write(rsp+0x38,bytes(uc.mem_read(rsp+0x28,0x8)))
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
    log.warning(f"HOOK_API_CALL : GetModuleFileNameW, path : {path}")
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
'''
def hook_RtlEnterCriticalSection(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
  
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
    
    log.warning(f"HOOK_API_CALL : RtlEnterCriticalSection, RCX : {hex(rcx)}")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
'''
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
    
    handle = EndOfString(bytes(uc.mem_read(rcx, 0xd)))
    log.warning(f"HOOK_API_CALL : GetModuleHandleA, RCX : {handle}")    
    #log.debug("DEBUGING")
    if handle in DLL_SETTING.LOADED_DLL:
        d_address = DLL_SETTING.LOADED_DLL[handle]

    if d_address:
        uc.reg_write(UC_X86_REG_RAX, d_address)

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
        PE_Loader(uc, dllName, GLOBALVAR['NEXT_DLL_BASE'])

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


'''
def hook_RtlInitializeCriticalSection(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbx))
    log.warning(f"HOOK_API_CALL : RtlInitializeCriticalSection, RCX : {hex(rcx)}")
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

'''
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


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : SetCurrentDirectoryW")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetCommandLineA(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetCommandLineA")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x000001E9E3860000+0x3480) #임시포인터
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_VirtualAlloc(ip, rsp, uc, log):
    global ALLOCATE_CHUNK_BASE
    global ALLOCATE_CHUNK_END
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
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
    log.warning(f"HOOK_API_CALL : VirtualAlloc, Address : {hex(offset)}, Size : {hex(rdx)}, Privilege : {hex(r9)}")
    uc.mem_write(rsp+0x8,struct.pack('<Q',offset))
    uc.mem_write(rsp+0x10,struct.pack('<Q',aligned_size))

    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,offset)
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
'''
def hook_AllocateAndInitializeSid(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : AllocateAndInitializeSid")
    
    #log.debug("DEBUGING")

    uc.reg_write(UC_X86_REG_RAX,0x1) 
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
'''
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

def hook_CloseHandle(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    
    
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : CloseHandle, handle : {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
def hook_FreeSid(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    
    
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : FreeSid")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
'''
def hook_RtlAddVectoredExceptionHandler(ip, rsp, uc, log):
    
    
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    
    #log.debug("DEBUGING")
  
    
    #print(path.encode("utf-8"))
    #print(hex(len(path)))
    log.warning(f"HOOK_API_CALL : RtlAddVectoredExceptionHandler")
    uc.mem_write(rsp+0x8,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbp))
    uc.mem_write(rsp+0x18,struct.pack('<Q',rsi))
   
    uc.reg_write(UC_X86_REG_RAX,0x000001E9E3860000) #임시 핸들
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
'''
'''
def hook_GetProcessHeap(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    rax =uc.mem_read(0xff20000000000000+0x30,8)
    rax =struct.unpack('<Q',rax)[0]
    
    log.warning(f"HOOK_API_CALL : GetProcessHeap, RAX : {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,rax)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    




def hook_RtlTryEnterCriticalSection(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    log.warning(f"HOOK_API_CALL : RtlTryEnterCriticalSection, RCX : {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
   


    
def hook_RtlLeaveCriticalSection(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    log.warning(f"HOOK_API_CALL : RtlLeaveCriticalSection, RCX : {hex(rcx)}")
    #log.debug("DEBUGING")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
   

def hook_GetCurrentDirectoryW(ip, rsp, uc, log):
    
    rdx = uc.reg_read(UC_X86_REG_RDX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    cwd = os.getcwd()
    cwd_len = len(cwd)
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetCurrentDirectoryW, path : {cwd}, len : {hex(cwd_len)}")
    
    uc.mem_write(rdx,cwd.encode('utf-8'))
    uc.reg_write(UC_X86_REG_RAX,cwd_len)
    uc.reg_write(UC_X86_REG_RCX,rdx)
    uc.reg_write(UC_X86_REG_R11,rdx)
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)





def hook_GetCurrentThreadId(ip, rsp, uc, log):
    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetCurrentThreadId")
    
   



def hook_GetVersion(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetVersion, Returning 6.2 (Windows 8 or Windows 10)")
    
    #log.debug("DEBUGING")

    uc.reg_write(UC_X86_REG_RAX,0x206) 
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)



def hook_RtlRemoveVectoredExceptionHandler(ip, rsp, uc, log):
    
    
    rbx = uc.reg_read(UC_X86_REG_RBX)
    rbp = uc.reg_read(UC_X86_REG_RBP)
    rsi = uc.reg_read(UC_X86_REG_RSI)
    rdi = uc.reg_read(UC_X86_REG_RDI)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    
    
  
    
    #print(path.encode("utf-8"))
    #print(hex(len(path)))
    log.warning(f"HOOK_API_CALL : RtlRemoveVectoredExceptionHandler")
    #log.debug("DEBUGING")
    uc.mem_write(rsp+0x8,struct.pack('<Q',rbx))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbp))
    uc.mem_write(rsp+0x18,struct.pack('<Q',rsi))
    uc.mem_write(rsp+0x20,struct.pack('<Q',rdi))
   
    uc.reg_write(UC_X86_REG_RAX,0x1) #임시 핸들
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)



def hook_GetCurrentProcess(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetCurrentProcess")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0xffffffffffffffff)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_CheckRemoteDebuggerPresent(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : CheckRemoteDebuggerPresent")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.mem_write(rsp+0x8,struct.pack('<Q',0x0))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbx))
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_VirtualProtect(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : VirtualProtect, RCX : {hex(rcx)}, RDX : {hex(rdx)}, R8 : {hex(r8)}, R9 : {hex(r9)}")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x1)
    uc.mem_write(rsp+0x8,struct.pack('<Q',0x0))
    uc.mem_write(rsp+0x10,struct.pack('<Q',rbx))
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_IsBadWritePtr(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    rbx = uc.reg_read(UC_X86_REG_RBX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : IsBadWritePtr, RCX : {hex(rcx)}, RDX : {hex(rdx)}")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetForegroundWindow(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetForegroundWindow")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
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

def hook_RaiseException(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : RaiseException")
    
    #log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetCurrentThread(ip, rsp, uc, log):

    log.warning(f"HOOK_API_CALL : GetCurrentThread")
    uc.reg_write(UC_X86_REG_RAX, 0xfffffffffffffffe)

    #log.debug("DEBUGING")
    ret = uc.mem_read(rsp,8)
    ret = struct.unpack('<Q',ret)[0]
    uc.reg_write(UC_X86_REG_RIP, ret)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)



def hook_GetTokenInformation(ip, rsp, uc, log):
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    #log.debug("DEBUGING")
    log.warning(f"HOOK_API_CALL : GetTokenInformation")
    token = uc.mem_read(0x1402615CC,8)
    print(struct.unpack('<Q',token)[0])
    uc.mem_write(0x1402615CC,struct.pack('<Q',0x1D4))
    log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RCX,0x1b4)
    uc.reg_write(UC_X86_REG_R8,0x7a)
    uc.reg_write(UC_X86_REG_R9,0x58)
    uc.reg_write(UC_X86_REG_R10,0x5)
    uc.reg_write(UC_X86_REG_R11,0x246)
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)




'''