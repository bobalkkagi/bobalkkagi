from unicorn import *
from unicorn.x86_const import *
from capstone import *
from loader import Insert_IAT, PE_Loader
from logger import *
from datetime import datetime
from api_hook import *
from config import DLL_SETTING, globar_var, InvHookFuncDict
from peb import SetLdr, SetListEntry, SetProcessHeap, setup_peb, SetKuserSharedData
from teb import *
from cache import hook_func

import logging
import config
import struct
import pefile
import os
# 64bit 맞게 수정
GS = 0xff10000000000000
IMAGE_BASE = 0x140000000
ADDRESS = 0x140000000
COUNT=0
Ldr = 0x000001B54C810000
PROC_HEAP_ADDRESS=0x000001E9E3850000
ALLOCATE_CHUNK=0x0000020000000000
STACK_BASE=0x201000
STACK_LIMIT= 0x100000
MB = 2**20 #Mega Byte
KUSER_SHARED_DATA = 0x000000007FFE0000
PSHIM_DATA = 0x600000
ACTIVATION_CONTEXT = 0x400000
DEBUGFLAG = False
HOOKINT=0
HOOKREGION=0x7FF010000000
BobLog = logging.getLogger("Bobalkkagi")


def hook_fetch(uc, access, address, size, value, user_data):
    
    print(hex(access),hex(address),hex(size),hex(value))
    rip=uc.reg_read(UC_X86_REG_RIP)
    print(hex(rip))

def hook_mem_read_unmapped(uc, access, address, size, value, user_dat):
    print("unmapped")
    print(hex(access), hex(address), hex(size), hex(value))

def hook_api(uc, address, size, user_data):
    global HOOKREGION
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    try:
        globals()["hook_"+globar_var.INV_HOOK_FUNC[address-HOOKREGION].split(".dll_")[1]](rip, rsp, uc, BobLog)
    except KeyError as e:
        BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass
    

def hook_block(uc, address, size, user_data):
    global DEBUGFLAG
    global HOOKINT
    exitFlag=0
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    
    '''
    tmp = {hex(address):size}
    
    if config.get_len() >=config.get_size():
        config.p_queue()
    config.i_queue(tmp)
    '''
    
    '''
    try :
       if rip in DLL_SETTING.INV_CACHE_DLL_FUNCTIONS:
            BobLog.info(f"This Function is {DLL_SETTING.INV_CACHE_DLL_FUNCTIONS[rip]}, RIP : {hex(rip)}")
            #BobLog.debug("DEBUGING")
            if DLL_SETTING.INV_CACHE_DLL_FUNCTIONS[rip].split('.dll_')[1] == "RtlVirtualUnwind":
                HOOKINT=uc.hook_add(UC_HOOK_CODE, InsPatch)
            
            if DLL_SETTING.INV_CACHE_DLL_FUNCTIONS[rip].split('.dll_')[1] == "RegOpenKeyExA":
                uc.hook_del(HOOKINT)
            
            
            exitFlag=globals()['hook_'+DLL_SETTING.INV_CACHE_DLL_FUNCTIONS[rip].split('.dll_')[1]](rip,rsp,uc,BobLog)
        
            if exitFlag ==1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass
    '''
    
    try :
       if rip in DLL_SETTING.INV_DLL_FUNCTIONS:
            BobLog.info(f"This Function is {DLL_SETTING.INV_DLL_FUNCTIONS[rip]}, RIP : {hex(rip)}")

            exitFlag = globals()["hook_"+DLL_SETTING.INV_DLL_FUNCTIONS[rip].split(".dll_")[1]](rip, rsp, uc, BobLog)
            if exitFlag == 1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass
    

    if DEBUGFLAG:
        BobLog.debug("DEBUGING")
        while True:
            ud = input("UNICORN DEBUG > ").lower()

            if ud == 'f':
                DEBUGFLAG = False
                print("FINISHED DEBUG")
                break
            elif ud == 'n':
                break
            elif ud == 's':
                while True:
                    try:
                        addr = input("address : ")
                        addr = int(addr, 16)
                        break
                    except:
                        print("input 0x1234")
                try:
                    print(f"result: {DLL_SETTING.INV_DLL_FUNCTIONS[addr]}")
                except:
                    print("No Search Result")

            elif ud == 'x':
                while True:
                    try:
                        addr, size = input("address size(min 0x8): ").split(' ')
                        addr = int(addr, 16)
                        size = int(size, 16)
                        break
                    except:
                        print("input 0x1234 0x8")
                try:
                    print(f"result: {uc.mem_read(addr, size)}")
                except:
                    print("No Search Result")
    
def hook_code(uc, address, size, user_data):
    global DEBUGFLAG
    global HOOKINT
    exitFlag=0
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
            #BobLog.debug("DEBUGING")
            
            exitFlag=globals()['hook_'+DLL_SETTING.INV_DLL_FUNCTIONS[rip].split('.dll_')[1]](rip,rsp,uc,BobLog)
        
            if exitFlag ==1:
                uc.emu_stop()
    except KeyError as e:
        BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass


    if DEBUGFLAG:
        BobLog.debug("DEBUGING")
        while True:
            ud = input("UNICORN DEBUG > ").lower()

            if ud == 'f':
                DEBUGFLAG = False
                print("FINISHED DEBUG")
                break
            elif ud == 'n':
                break
            elif ud == 's':
                while True:
                    try:
                        addr = input("address : ")
                        addr = int(addr, 16)
                        break
                    except:
                        print("input 0x1234")
                try:
                    print(f"result: {DLL_SETTING.INV_DLL_FUNCTIONS[addr]}")
                except:
                    print("No Search Result")

            elif ud == 'x':
                while True:
                    try:
                        addr, size = input("address size(min 0x8): ").split(' ')
                        addr = int(addr, 16)
                        size = int(size, 16)
                        break
                    except:
                        print("input 0x1234 0x8")
                try:
                    print(f"result: {uc.mem_read(addr, size)}")
                except:
                    print("No Search Result")
    
    

def InsPatch(uc, address, size, user_data):
    global HOOKINT
    rip=uc.reg_read(UC_X86_REG_RIP)
    rsp=uc.reg_read(UC_X86_REG_RSP)
    if size ==0xf1f1f1f1 :
        size = 0x3
    code = uc.mem_read(address, size)
    
    asm=disas(bytes(code),address)
    for a in asm:
        if a.mnemonic == "xrstor":
            uc.reg_write(UC_X86_REG_RIP,rip+0x3)
        if a.mnemonic == "iretq":
            nrip=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
            nflags=struct.unpack('<Q',uc.mem_read(rsp+0x10,8))[0]
            nrsp=struct.unpack('<Q',uc.mem_read(rsp+0x18,8))[0]
            uc.reg_write(UC_X86_REG_RIP, nrip)
            uc.reg_write(UC_X86_REG_RSP, nrsp)
            uc.reg_write(UC_X86_REG_EFLAGS, nflags)
            uc.hook_del(HOOKINT)

def InsertHookFlag(uc):
    global HOOKREGION
    for key in hook_func:
        address = DLL_SETTING.DLL_FUNCTIONS[key]
        offset = HOOKREGION-address-5 + hook_func[key]
        byteOffset=struct.pack('<Q',offset)
        jmp = struct.pack('<B',0xE9)
        flagInstruction = (jmp+byteOffset)[:-1]
        uc.mem_write(address,flagInstruction)

def setup_teb(uc):
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
    uc.mem_map(ACTIVATION_CONTEXT, 0x1000, UC_PROT_ALL)
   
    uc.mem_map(KUSER_SHARED_DATA, 0x1000, UC_PROT_READ) # KUSER_SHARED_DATA 구조체 만들어서 셋팅하기
    
    uc.mem_map(PSHIM_DATA, 0x2000, UC_PROT_READ | UC_PROT_WRITE)

    uc.reg_write(UC_X86_REG_GS_BASE, teb_addr)
    uc.reg_write(UC_X86_REG_CS, 0x400000)

def emulate(program: str,  verbose):
    
    start = datetime.now()
    print(f"[{start}]Emulating Binary!")
    global InvDllFunctions
    global HOOKINT
    global HOOKREGION
    pe = pefile.PE(program) # 실행할 프로그램 pe포멧으로 가져오기
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    setup_logger(uc, BobLog, verbose) #debuging 용 logger

    EP = pe.OPTIONAL_HEADER.AddressOfEntryPoint #Entry Point
    uc.mem_map(STACK_LIMIT, STACK_BASE - STACK_LIMIT, UC_PROT_ALL) #스택 공간
    
    PE_Loader(uc,program,ADDRESS)
    
    setup_teb(uc)
    setup_peb(uc)
    SetProcessHeap(uc)
    SetKuserSharedData(uc)
    
    uc.mem_map(HOOKREGION,0x1000,UC_PROT_ALL)
    
    
    config.InvDllDict() # 함수 이름 : 주소 , -> 주소 : 이름

    #uc.reg_write(UC_X86_REG_RSP, STACK_BASE - pe.OPTIONAL_HEADER.SectionAlignment) #0x200000
    uc.reg_write(UC_X86_REG_RSP, 0x14ff28) #0x200000
    uc.reg_write(UC_X86_REG_RBP, 0x0) 
    
    InsertHookFlag(uc)
    InvHookFuncDict()
    
    print("hook start!")
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped)
    #uc.hook_add(UC_HOOK_CODE, hook_code)
    #uc.hook_add(UC_HOOK_BLOCK, hook_block) 
    #uc.hook_add(UC_HOOK_BLOCK, hook_block, None,  0x7ff000000000,  0x7ff001000000)
    print(hex(DLL_SETTING.LOADED_DLL["ntdll.dll"]), hex(DLL_SETTING.LOADED_DLL["kernel32.dll"]))
    uc.hook_add(UC_HOOK_CODE, InsPatch, None,  DLL_SETTING.LOADED_DLL["ntdll.dll"], DLL_SETTING.LOADED_DLL["kernelbase.dll"])
    uc.hook_add(UC_HOOK_BLOCK, hook_api, None, HOOKREGION, HOOKREGION+0x1000) 
    
    uc.reg_write(UC_X86_REG_RAX, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_RBX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, 0xff20000000000000)
    uc.reg_write(UC_X86_REG_RDX, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_R8, 0xff20000000000000)
    uc.reg_write(UC_X86_REG_R9, ADDRESS+EP)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x244)
    #uc.mem_write(0x140003020,struct.pack('<Q',0x5A0058))
    
    ### 안티디버깅 우회에 필요한 셋팅 
    #uc.mem_write(0x7ff00050a040,struct.pack('<Q',0xB0)) kernelbasr 값
    #uc.mem_write(0x7ff00017187e,struct.pack('<B',0x90)) <- ntdll값
   
    ###
    

    #P_DLL_Function()
    #P_LOADED_DLL()
   
    uc.mem_protect(0x140001000,0x1000,UC_PROT_READ)
    globar_var.SECTIONINFO[0][2]=0x2
    print("PID : ",os.getpid())
    try:
        uc.emu_start(IMAGE_BASE + EP, ADDRESS)
    except UcError as e:
        print(f"[ERROR]: {e}")
        BobLog.info("Find OEP : %s" % hex(uc.reg_read(UC_X86_REG_RIP)))
        #print(hex(uc.reg_read(UC_X86_REG_RIP)))
        #BobLog.debug("DEBUGING")
  
    end = datetime.now()
    print(f"[{end}] Emulation done...")
    print(f"Runtime: [{end-start}]")


def P_DLL_Function():
    for key in DLL_SETTING.DLL_FUNCTIONS:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.DLL_FUNCTIONS[key])))
    

def P_INV_DLL_Function():
    for key in DLL_SETTING.INV_DLL_FUNCTIONS:
        print("key : {0}, value : {1}".format(hex(key),DLL_SETTING.INV_DLL_FUNCTIONS[key]))

def P_LOADED_DLL():
    for key in DLL_SETTING.LOADED_DLL:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.LOADED_DLL[key])))

def P_CACHE_DLL_Function():
    for key in DLL_SETTING.CACHE_DLL_FUNCTIONS:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.CACHE_DLL_FUNCTIONS[key])))

def P_INV_CACHE_DLL_Function():
    for key in DLL_SETTING.INV_CACHE_DLL_FUNCTIONS:
        print("key : {0}, value : {1}".format(hex(key),DLL_SETTING.INV_CACHE_DLL_FUNCTIONS[key]))
