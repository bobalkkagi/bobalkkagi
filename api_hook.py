from unicorn import *
from unicorn.x86_const import *
from loader import EndOfString
from config import DLL_SETTING

import struct
def hook_LoadLibraryA(ip, rsp, uc):
    print("========LoadLibraryA========")
    
    rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
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

    print(f"{dllName}: {hex(d_address)}")

    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    print("=========End LoadLibraryA========")

def hook_GetProcAddress(ip, rsp, uc):
    print("========GetProcAddress========")
    

    rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    f_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    #func_nameByte = bytes(uc.mem_read(rdx, 0x20))
    
    
    functionName=EndOfString(bytes(uc.mem_read(rdx, 0x20)))
    print(DLL_SETTING.INV_LOADED_DLL[rcx],functionName)
    functionName = DLL_SETTING.INV_LOADED_DLL[rcx]+"_" + functionName
    f_address = DLL_SETTING.DLL_FUNCTIONS[functionName]

    print(f"{functionName}: {hex(f_address)}")

    if f_address:
        uc.reg_write(UC_X86_REG_RAX,f_address)

    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    print("============================")

def hook_GetModuleHandleA(ip, rsp, uc):
    print("========GetModuleHandleA========")
    
    #rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    #rdx = uc.reg_read(UC_X86_REG_RDX)
    #r8 = uc.reg_read(UC_X86_REG_R8)
    #r9 = uc.reg_read(UC_X86_REG_R9)
    d_address = 0
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    

    handle = EndOfString(bytes(uc.mem_read(rcx, 0xd)))
    
    print(f"RCX : {handle}")

    if handle in DLL_SETTING.LOADED_DLL:
        d_address = DLL_SETTING.LOADED_DLL[handle]

    if d_address:
        uc.reg_write(UC_X86_REG_RAX, d_address)

    uc.reg_write(UC_X86_REG_RIP, tmp)
    uc.reg_write(UC_X86_REG_RSP, rsp+8)
    print("============================")

def hook_RtlInitializeCriticalSection(ip, rsp, uc):
    print("========RtlInitializeCriticalSection========")
    
    #rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    #rdx = uc.reg_read(UC_X86_REG_RDX)
    #r8 = uc.reg_read(UC_X86_REG_R8)
    #r9 = uc.reg_read(UC_X86_REG_R9)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
    print("RCX : ",rcx)
    
    
    uc.reg_write(UC_X86_REG_RAX,0x0)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    print("============================")

def hook_GetUserDefaultUILanguage(ip,rsp, uc):
    print("========GetUserDefaultUILanguage========")
    
    #rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    #rdx = uc.reg_read(UC_X86_REG_RDX)
    #r8 = uc.reg_read(UC_X86_REG_R8)
    #r9 = uc.reg_read(UC_X86_REG_R9)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    
    print("RCX : ",rcx)
    
    
    uc.reg_write(UC_X86_REG_RAX,0x409)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    print("============================")

def hook_GetProcessHeap(ip, rsp, uc):
    print("========GetProcessHeap========")
    
    #rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    #rdx = uc.reg_read(UC_X86_REG_RDX)
    #r8 = uc.reg_read(UC_X86_REG_R8)
    #r9 = uc.reg_read(UC_X86_REG_R9)
    tmp = uc.mem_read(rsp,8)
    tmp=struct.unpack('<Q',tmp)[0]
    
    rax =uc.mem_read(0xff20000000000000+0x30,8)
    rax =struct.unpack('<Q',rax)[0]
    print("RAX : ", rax)
    
    
    uc.reg_write(UC_X86_REG_RAX,rax)
    uc.reg_write(UC_X86_REG_RIP,tmp)
    uc.reg_write(UC_X86_REG_RSP,rsp+8)
    print("============================")

def hook_RtlAllocateHeap(ip, rsp, uc):
    print("========RtlAllocateHeap========")
    
    #rax = uc.reg_read(UC_X86_REG_RAX)
    rcx = uc.reg_read(UC_X86_REG_RCX)
    rdx = uc.reg_read(UC_X86_REG_RDX)
    r8 = uc.reg_read(UC_X86_REG_R8)
    r9 = uc.reg_read(UC_X86_REG_R9)
    


    print("RCX : ", hex(rcx))
    
    print("RDX : ", hex(rdx))
    
    print("R8 : ", hex(r8))
    
    print("R9 : ", hex(r9))
    
    print("============================")