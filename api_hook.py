from unicorn import *
from unicorn.x86_const import *
from loader import EndOfString
from config import DLL_SETTING, HEAP_HANDLE

import logging
import struct
import os


def hook_LoadLibraryA(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)

    d_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    dllName = EndOfString(bytes(uc.mem_read(rcx, 0x20))) #byte string
    
    if dllName in DLL_SETTING.LOADED_DLL:
        d_address = DLL_SETTING.LOADED_DLL[dllName]
    else:
        print(f"{dllName} is not Loaded!")
    
    if d_address:
        uc.reg_write(UC_X86_REG_RAX,d_address)

    log.info(f"API Call : LoadLibraryA, {dllName}: {hex(d_address)}")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    

def hook_GetProcAddress(ip, rsp, uc, log):
    
    INV_LOADED_DLL = {v: k for k, v in DLL_SETTING.LOADED_DLL.items()}

    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
  
    f_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    #func_nameByte = bytes(uc.mem_read(rdx, 0x20))
    
    
    functionName=EndOfString(bytes(uc.mem_read(rdx, 0x20)))
    functionName = INV_LOADED_DLL[rcx]+"_" + functionName
    f_address = DLL_SETTING.DLL_FUNCTIONS[functionName]

    
    log.info(f"API Call : GetProcAddress, {functionName}: {hex(f_address)}")
    if f_address:
        uc.reg_write(UC_X86_REG_RAX,f_address)

    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetModuleHandleA(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    d_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    

    handle = EndOfString(bytes(uc.mem_read(rcx, 0xd)))
    log.info(f"API Call : GetModuleHandleA, RCX : {handle}")    

    if handle in DLL_SETTING.LOADED_DLL:
        d_address = DLL_SETTING.LOADED_DLL[handle]

    if d_address:
        uc.reg_write(UC_X86_REG_RAX, d_address)

    uc.reg_write(UC_X86_REG_RIP, tmp)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)

def hook_RtlInitializeCriticalSection(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    log.info(f"API Call : RtlInitializeCriticalSection, RCX : {hex(rcx)}")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    

def hook_GetUserDefaultUILanguage(ip,rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
   
    log.info(f"API Call : GetUserDefaultUILanguage, RCX : {hex(rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x409)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    

def hook_GetProcessHeap(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    rax =uc.mem_read(0xff20000000000000+0x30,8)
    rax =struct.unpack('<Q',rax)[0]
    
    log.info(f"API Call : GetProcessHea, RAX : {hex(rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX,rax)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    

def hook_RtlAllocateHeap(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    r8 = uc.reg_read(UC_X86_REG_R8)

    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    HEAP_HANDLE.heap_handle.append(HEAP_HANDLE.heap_handle[HEAP_HANDLE.heap_handle_size-1]+(r8*8))
    HEAP_HANDLE.heap_handle_size+=1

    uc.reg_write(UC_X86_REG_RAX,HEAP_HANDLE.heap_handle[HEAP_HANDLE.heap_handle_size-1])
   
    log.info(f"API Call : RtlAllocateHeap, RAX : {hex(HEAP_HANDLE.heap_handle[HEAP_HANDLE.heap_handle_size-1])}")
    
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    

def hook_RtlTryEnterCriticalSection(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    log.info(f"API Call : RtlTryEnterCriticalSection, RCX : {hex(rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
   

def hook_RtlEnterCriticalSection(ip, rsp, uc, log):
    
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
  
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
    
    log.info(f"API Call : RtlEnterCriticalSection, RCX : {hex(rcx)}")
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    
def hook_RtlLeaveCriticalSection(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
   
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    log.info(f"API Call : RtlLeaveCriticalSection, RCX : {hex(rcx)}")
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
   

def hook_GetCurrentDirectoryW(ip, rsp, uc, log):
    
    rdx = uc.reg_read(UC_X86_REG_RDX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]


    cwd = os.getcwd()
    cwd_len = len(cwd)
    
    log.info(f"API Call : GetCurrentDirectoryW, path : {cwd}, len : {hex(cwd_len)}")
    
    uc.mem_write(rdx,cwd.encode('utf-8'))
    uc.reg_write(UC_X86_REG_RAX,cwd_len)
    uc.reg_write(UC_X86_REG_RCX,rdx)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)

def hook_GetModuleFileNameW(ip, rsp, uc, log):
    
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]

    if not rcx:
        path = "C:\\Users\\kor15\\Desktop\\practice\\bob\\Bobalkkagi_test\\Project8_protected.exe"
    else:
        try:
            module_name = DLL_SETTING.LOADED_DLL[rcx]
        except KeyError:
            module_name = "somefakename.dll"
        path = f"C:/Windows/System32/{module_name}"
    
    log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_R11,rdx)
    
    #print(path.encode("utf-8"))
    #print(hex(len(path)))
    log.info(f"API Call : GetModuleFileNameW, path : {path}")
    
    uc.mem_write(rdx,path.encode("utf-8"))
    uc.reg_write(UC_X86_REG_RAX,len(path))
    uc.reg_write(UC_X86_REG_RDX,0x0)
    uc.reg_write(UC_X86_REG_R8,0x0)
    log.debug("DEBUGING")
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)