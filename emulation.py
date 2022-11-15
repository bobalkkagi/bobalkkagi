from unicorn import *
from unicorn.x86_const import *
from capstone import *
from loader import Insert_IAT, PE_Loader
from logger import *
from datetime import datetime
from api_hook import *
from config import DLL_SETTING
from peb import SetLdr, SetListEntry, SetProcessHeap, SetPEB
from teb import *

import logging
import config
import struct
import pefile
import os
# 64bit 맞게 수정
GS = 0xff10000000000000
IMAGE_BASE = 0x140000000
ADDRESS = 0x140000000
DLL_BASE = 0x800000
COUNT=0
Ldr = 0x000001B54C810000
PROC_HEAP_ADDRESS=0x000001E9E3850000
ALLOCATE_CHUNK=0x0000020000000000
STACK_BASE=0x201000
STACK_LIMIT= 0x100000
MB = 2**20 #Mega Byte

#DLL_FUNCTIONS={} # {function name: address}
#LOADED_DLL = {} # {dll: address}

BobLog = logging.getLogger("Bobalkkagi")



def hook_fetch(uc, access, address, size, value, user_data):
    
    print(hex(access),hex(address),hex(size),hex(value))
    rip=uc.reg_read(UC_X86_REG_RIP)
    print(hex(rip))


def hook_block(uc, address, size, user_data):
    
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    
    #BobLog.debug("DEBUGING")
    
    tmp = {hex(address):size}
    
    if config.get_len() >=config.get_size():
        config.p_queue()
    config.i_queue(tmp)
   
    try :
       if rip in DLL_SETTING.INV_DLL_FUNCTIONS:
            BobLog.info(f"This Function is {DLL_SETTING.INV_DLL_FUNCTIONS[rip]}, RIP : {hex(rip)}")
            exitFlag=globals()['hook_'+DLL_SETTING.INV_DLL_FUNCTIONS[rip].split('.dll_')[1]](rip,rsp,uc,BobLog)
            if exitFlag ==1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass

def hook_code(uc, address, size, user_data):
    
    exitFlag=0
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    
    global COUNT
    global ADDRESS
    
    
    tmp = {hex(address):size}
    
    if config.get_len() >=config.get_size():
        config.p_queue()
    config.i_queue(tmp)
    #BobLog.debug("DEBUGING")
    try :
       if rip in DLL_SETTING.INV_DLL_FUNCTIONS:
            BobLog.info(f"This Function is {DLL_SETTING.INV_DLL_FUNCTIONS[rip]}, RIP : {hex(rip)}")
            exitFlag=globals()['hook_'+DLL_SETTING.INV_DLL_FUNCTIONS[rip].split('.dll_')[1]](rip,rsp,uc,BobLog)
            if exitFlag ==1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass
    
    



def setup_teb(uc):
    global HEAP_BASE
    teb_addr = 0xff10000000000000
    peb_addr = 0xff20000000000000
    teb = InitTeb()
    teb_payload = bytes(teb)
    uc.mem_map(teb_addr, 2 * 1024 * 1024,UC_PROT_ALL)
    uc.mem_map(peb_addr, 2 * 1024 * 1024,UC_PROT_ALL)
    uc.mem_map(Ldr, 1 * MB, UC_PROT_ALL)
    uc.mem_map(PROC_HEAP_ADDRESS, 10 * MB, UC_PROT_ALL)
    uc.mem_map(ALLOCATE_CHUNK, 10 * MB, UC_PROT_ALL)
    uc.mem_write(teb_addr, teb_payload)
    uc.mem_write(peb_addr+ 0x30, struct.pack('<Q', PROC_HEAP_ADDRESS))
    uc.mem_write(PROC_HEAP_ADDRESS+0x1db0,struct.pack('<Q',0x5A0058))
    uc.mem_write(PROC_HEAP_ADDRESS+0x1db8,struct.pack('<Q',PROC_HEAP_ADDRESS+0x2398))


    uc.reg_write(UC_X86_REG_GS_BASE, teb_addr)
    uc.reg_write(UC_X86_REG_CS, 0x400000)

def emulate(program: str,  verbose):
    
    start = datetime.now()
    print(f"[{start}]Emulating Binary!")
    global InvDllFunctions


    pe = pefile.PE(program)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    setup_logger(uc, BobLog, verbose)

    EP = pe.OPTIONAL_HEADER.AddressOfEntryPoint #Entry Point
    uc.mem_map(STACK_LIMIT, STACK_BASE - STACK_LIMIT)
    
    PE_Loader(uc,program,ADDRESS)
    

    
    setup_teb(uc)
    '''
    SetLdr(uc) # Ldr set     load된 dll마다 추가해줘야 함
    for i in range(0,4):  # ListEntry set 
        SetListEntry(uc,dllList[i],i)
    '''
    uc.mem_write(PROC_HEAP_ADDRESS+0x2398,os.path.abspath(program).encode("utf-8"))
    SetPEB(uc)
    SetProcessHeap(uc)

    config.InvDllDict()

    uc.reg_write(UC_X86_REG_RSP, STACK_BASE - pe.OPTIONAL_HEADER.SectionAlignment) #0x200000
    uc.reg_write(UC_X86_REG_RBP, 0x0) #0x200600a
    
    print("hook start!")
    uc.hook_add(UC_HOOK_CODE, hook_code)
    #uc.hook_add(UC_HOOK_BLOCK, hook_block)
   
    uc.reg_write(UC_X86_REG_RAX, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_RDX, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_R9, ADDRESS+EP)
    uc.mem_write(0x140003020,struct.pack('<Q',0x5A0058))
    #uc.mem_write(0x100F794,struct.pack('<Q',0x1))
    
    
    '''
    for key in DLL_SETTING.DLL_FUNCTIONS:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.DLL_FUNCTIONS[key])))
    
    print("=================================================")
    for key in DLL_SETTING.LOADED_DLL:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.LOADED_DLL[key])))
    '''

    try:
        uc.emu_start(IMAGE_BASE + EP, ADDRESS)
    except UcError as e:
        print(f"[ERROR]: {e}")
        BobLog.debug("DEBUGING")
  
    end = datetime.now()
    print(f"[{end}] Emulation done...")
    print(f"Runtime: [{end-start}]")
    
