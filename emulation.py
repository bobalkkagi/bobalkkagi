from unicorn import *
from unicorn.x86_const import *
from capstone import *
from loader import DLL_Loader, Insert_IAT, EndOfString
from logger import *
from datetime import datetime

import logging
import config
import struct
import pefile


GS = 0xff10000000000000
ADDRESS = 0x140000000
DLL_BASE = 0x800000

STACK_BASE=0x201000
STACK_LIMIT= 0x100000
HEAP_BASE=0x18476850000
MB = 2**20 #Mega Byte

DLL_FUNCTIONS={} # {function name: address}
LOADED_DLL = {} # {dll: address}

BobLog = logging.getLogger("Bobalkkagi")

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
    
    if dllName in LOADED_DLL:
        d_address = LOADED_DLL[dllName]
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

    f_address = DLL_FUNCTIONS[EndOfString(bytes(uc.mem_read(rdx, 0x20)))]

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

    if handle in LOADED_DLL:
        d_address = LOADED_DLL[handle]

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
    
    BobLog.debug("info")
    print("============================")

def disas(code,address):
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    assem=md.disasm(code,address)
    return assem

def hook_fetch(uc, access, address, size, value, user_data):
    
    print(hex(access),hex(address),hex(size),hex(value))
    rip=uc.reg_read(UC_X86_REG_RIP)
    print(hex(rip))


def hook_block(uc, address, size, user_data):
    rbp=uc.reg_read(UC_X86_REG_RBP)
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    rax=uc.reg_read(UC_X86_REG_RAX)
    rbx=uc.reg_read(UC_X86_REG_RBX)
    rcx=uc.reg_read(UC_X86_REG_RCX)
    rdx=uc.reg_read(UC_X86_REG_RDX)
    rdi=uc.reg_read(UC_X86_REG_RDI)
    rsi=uc.reg_read(UC_X86_REG_RSI)
    
    gs = uc.reg_read(UC_X86_REG_GS)
    gs_base = uc.reg_read(UC_X86_REG_GS_BASE)
    gdtr = uc.reg_read(UC_X86_REG_GDTR)

    reg_rsp = uc.mem_read(rsp,0x8)
    
    # read this instruction code from memory
    code = uc.mem_read(address, size)
   
    if rip in InvDllFunctions:
        globals()['hook_'+InvDllFunctions[rip]](rip,rsp,uc)
    print("")
    

def hook_code(uc, address, size, user_data):
    
    #rbp=uc.reg_read(UC_X86_REG_RBP)
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    #rax=uc.reg_read(UC_X86_REG_RAX)
    #rbx=uc.reg_read(UC_X86_REG_RBX)
    #rcx=uc.reg_read(UC_X86_REG_RCX)
    #rdx=uc.reg_read(UC_X86_REG_RDX)
    #rdi=uc.reg_read(UC_X86_REG_RDI)
    #rsi=uc.reg_read(UC_X86_REG_RSI)
    
    #gs = uc.reg_read(UC_X86_REG_GS)
    #gs_base = uc.reg_read(UC_X86_REG_GS_BASE)
    #gdtr = uc.reg_read(UC_X86_REG_GDTR)

    tmp = {hex(address):size}
    
    if config.get_len() >=config.get_size():
        config.p_queue()
    config.i_queue(tmp)

    if rip in InvDllFunctions:
        globals()['hook_'+InvDllFunctions[rip]](rip,rsp,uc)


def setup_teb(uc):
    global HEAP_BASE
    teb_addr = 0xff10000000000000
    peb_addr = 0xff20000000000000
    
    uc.mem_map(teb_addr, 2 * 1024 * 1024,UC_PROT_ALL)
    uc.mem_map(peb_addr, 2 * 1024 * 1024,UC_PROT_ALL)
    uc.mem_write(teb_addr + 0x30, struct.pack('<Q', teb_addr))
    uc.mem_write(teb_addr + 0x60, struct.pack('<Q', peb_addr))
    uc.mem_write(peb_addr+ 0x30, struct.pack('<Q', HEAP_BASE))

    uc.reg_write(UC_X86_REG_GS_BASE, teb_addr)
    uc.reg_write(UC_X86_REG_CS, 0x400000)

def emulate(program: str,  verbose):

    print("Emulating Binary!")
    global InvDllFunctions

    DLL_ADDRESS = 0x800000

    pe = pefile.PE(program)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    setup_logger(uc, BobLog, verbose)

    EP = pe.OPTIONAL_HEADER.AddressOfEntryPoint #Entry Point

    uc.mem_map(ADDRESS, 20*MB, UC_PROT_ALL)
    uc.mem_map(DLL_BASE, 50*MB, UC_PROT_ALL)
    uc.mem_map(STACK_LIMIT, STACK_BASE - STACK_LIMIT)
    uc.mem_write(ADDRESS, pe.header)
    
    for section in pe.sections:
        code = section.get_data()
        uc.mem_write(ADDRESS + section.VirtualAddress, code)
        if b'.boot' in section.Name:
            bootSize = section.VirtualAddress + section.Misc_VirtualSize

    dllList = [
        "kernel32.dll", "ntdll.dll", 
        "user32.dll", "ucrtbase.dll",
        "vcruntime140d.dll", "win32u.dll",
        "win32u.dll", "gdi32.dll",
        "msvcp_win.dll", "msvcp_win.dll",
        "advapi32.dll", "shell32.dll", "shlwapi.dll"
        ]
    
    #Load dll
    for dll in dllList:
        DLL_ADDRESS = DLL_Loader(uc, dll, DLL_ADDRESS, LOADED_DLL, DLL_FUNCTIONS)

    setup_teb(uc)

    Insert_IAT(uc, pe, ADDRESS, LOADED_DLL, DLL_FUNCTIONS, DLL_ADDRESS)
    
    InvDllFunctions = {v: k for k, v in DLL_FUNCTIONS.items()}
    
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE - 0x1000) #0x200000
    uc.reg_write(UC_X86_REG_RBP, 0x0) #0x200600
    
    print("hook start!")
    uc.hook_add(UC_HOOK_CODE, hook_code)
   
    uc.reg_write(UC_X86_REG_RAX, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_RDX, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_R9, ADDRESS+EP)

    try:
        uc.emu_start(ADDRESS + EP, ADDRESS + EP + bootSize)
    except UcError as e:
        print(f"[ERROR]: {e}")
        BobLog.info("DEBUGING")

    print(f"[{datetime.now()}] Emulation done...") 
    
