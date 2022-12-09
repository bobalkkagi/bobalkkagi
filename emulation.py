from unicorn import *
from unicorn.x86_const import *
from capstone import *
from loader import Insert_IAT, PE_Loader
from logger import *
from datetime import datetime
from api_hook import *
from globalValue import DLL_SETTING, GLOBAL_VAR, InvHookFuncDict
from peb import SetLdr, SetListEntry, SetProcessHeap, setup_peb, SetKuserSharedData
from teb import *
from hookFuncs import HookFuncs
from constValue import *
from util import *

import logging
import globalValue
import struct
import pefile
import os

# 64bit 맞게 수정


BobLog = logging.getLogger("Bobalkkagi")


def hook_fetch(uc, access, address, size, value, user_data):
    
    print(hex(access),hex(address),hex(size),hex(value))
    rip=uc.reg_read(UC_X86_REG_RIP)
    print(hex(rip))

def hook_mem_read_unmapped(uc, access, address, size, value, user_dat):
    print("unmapped")
    print(hex(access), hex(address), hex(size), hex(value))
    code = uc.mem_read(address, size)
    asm=disas(bytes(code),address)
    print(code)
    print(asm)
    print("hi")
    
    for a in asm:
        print("  0x%x: " % a.address +"\t%s" % a.mnemonic +"\t%s\n" % a.op_str)
        

def hook_api(uc, address, size, user_data):
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    try:
        globals()["hook_"+GLOBAL_VAR.InverseHookFuncs[address-GLOBAL_VAR.HookRegion].split(".dll_")[1]](rip, rsp, uc, BobLog)
    except KeyError as e:
        BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass
    

def hook_block(uc, address, size, user_data):
    exitFlag=0
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    
    '''
    tmp = {hex(address):size}
    
    if config.get_len() >=config.get_size():
        config.p_queue()
    config.i_queue(tmp)
    '''
    
    
    try :
       if rip in DLL_SETTING.InverseDllFuncs:
            BobLog.info(f"This Function is {DLL_SETTING.InverseDllFuncs[rip]}, RIP : {hex(rip)}")

            exitFlag = globals()["hook_"+DLL_SETTING.InverseDllFuncs[rip].split(".dll_")[1]](rip, rsp, uc, BobLog)
            if exitFlag == 1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass
    

    if GLOBAL_VAR.DebugFlag:
        BobLog.debug("DEBUGING")
        while True:
            ud = input("UNICORN DEBUG > ").lower()

            if ud == 'f':
                GLOBAL_VAR.DebugFlag = False
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
                    print(f"result: {DLL_SETTING.InverseDllFuncs[addr]}")
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
    exitFlag=0
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    #BobLog.debug("DEBUGING")
    
    tmp = {hex(address):size}
    
    if globalValue.get_len() >=globalValue.get_size():
        globalValue.p_queue()
    globalValue.i_queue(tmp)
    
   
    try :
       if rip in DLL_SETTING.InverseDllFuncs:
            BobLog.info(f"This Function is {DLL_SETTING.InverseDllFuncs[rip]}, RIP : {hex(rip)}")
            #BobLog.debug("DEBUGING")
            
            exitFlag=globals()['hook_'+DLL_SETTING.InverseDllFuncs[rip].split('.dll_')[1]](rip,rsp,uc,BobLog)
        
            if exitFlag ==1:
                uc.emu_stop()
    except KeyError as e:
        BobLog.info("Not Found : "+str(e))
        #BobLog.debug("DEBUGING")
        pass


    if GLOBAL_VAR.DebugFlag:
        BobLog.debug("DEBUGING")
        while True:
            ud = input("UNICORN DEBUG > ").lower()

            if ud == 'f':
                GLOBAL_VAR.DebugFlag = False
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
                    print(f"result: {DLL_SETTING.InverseDllFuncs[addr]}")
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
            uc.hook_del(GLOBAL_VAR.HookInt)

def InsertHookFlag(uc):
    for key in HookFuncs:
        address =DLL_SETTING.DllFuncs[key]
        offset = GLOBAL_VAR.HookRegion-address-5 + HookFuncs[key]
        byteOffset=struct.pack('<Q',offset)
        jmp = struct.pack('<B',0xE9)
        flagInstruction = (jmp+byteOffset)[:-1]
        uc.mem_write(address,flagInstruction)

def setup_teb(uc):
    
    teb = InitTeb()
    teb_payload = bytes(teb)
    uc.mem_map(TebAddress, 2 * MB, UC_PROT_ALL)
    uc.mem_map(PebAddress, 2 * MB, UC_PROT_ALL)
    uc.mem_map(Ldr, 1 * MB, UC_PROT_ALL)
    uc.mem_map(ProcHeapAddress, 10 * MB, UC_PROT_ALL)
    uc.mem_write(TebAddress, teb_payload)
    uc.mem_write(PebAddress+ 0x30, struct.pack('<Q', ProcHeapAddress))
    uc.mem_map(ActivationContext, 0x1000, UC_PROT_ALL)
   
    uc.mem_map(KuserSharedData, 0x1000, UC_PROT_READ) # KUSER_SHARED_DATA 구조체 만들어서 셋팅하기
    
    uc.mem_map(PshimData, 0x2000, UC_PROT_READ | UC_PROT_WRITE)

    uc.reg_write(UC_X86_REG_GS_BASE, TebAddress)
    uc.reg_write(UC_X86_REG_CS, 0x400000)

def emulate(program: str,  verbose):
    
    start = datetime.now()
    print(f"[{start}]Emulating Binary!")
    pe = pefile.PE(program) # 실행할 프로그램 pe포멧으로 가져오기
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    setup_logger(uc, BobLog, verbose) #debuging 용 logger

    EP = pe.OPTIONAL_HEADER.AddressOfEntryPoint #Entry Point
    uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL) #스택 공간
    
    PE_Loader(uc, program, GLOBAL_VAR.ImageBaseStart)
    
    setup_teb(uc)
    setup_peb(uc)
    SetProcessHeap(uc)
    SetKuserSharedData(uc)
    
    uc.mem_map(GLOBAL_VAR.HookRegion, 0x1000, UC_PROT_ALL)
    
    
    globalValue.InvDllDict() # 함수 이름 : 주소 , -> 주소 : 이름

    #uc.reg_write(UC_X86_REG_RSP, STACK_BASE - pe.OPTIONAL_HEADER.SectionAlignment) #0x200000
    uc.reg_write(UC_X86_REG_RSP, 0x14ff28) #0x200000
    uc.reg_write(UC_X86_REG_RBP, 0x0) 
    
    InsertHookFlag(uc)
    InvHookFuncDict()
    
    print("hook start!")

    #uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped)
    uc.hook_add(UC_HOOK_MEM_WRITE_PROT, hook_mem_read_unmapped)
    #uc.hook_add(UC_HOOK_CODE, hook_code)
    #uc.hook_add(UC_HOOK_BLOCK, hook_block) 
    
    uc.hook_add(UC_HOOK_CODE, InsPatch, None,  DLL_SETTING.LoadedDll["ntdll.dll"], DLL_SETTING.LoadedDll["kernelbase.dll"])
    #uc.hook_add(UC_HOOK_BLOCK, hook_block, None,  0x7ff000000000,  0x800000000000)
    uc.hook_add(UC_HOOK_BLOCK, hook_api, None, GLOBAL_VAR.HookRegion, GLOBAL_VAR.HookRegion + 0x1000) 
    
    uc.reg_write(UC_X86_REG_RAX, GLOBAL_VAR.ImageBaseStart+EP)
    uc.reg_write(UC_X86_REG_RBX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, PebAddress)
    uc.reg_write(UC_X86_REG_RDX, GLOBAL_VAR.ImageBaseStart+EP)
    uc.reg_write(UC_X86_REG_R8, PebAddress)
    uc.reg_write(UC_X86_REG_R9, GLOBAL_VAR.ImageBaseStart+EP)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x244)
   

    '''
    for key in GLOBAL_VAR.SectionInfo:
        print("address : {0}, size : {1}, priv : {2}".format(hex(key[0]),hex(key[1]),hex(key[2])))
    '''
    ### Find OEP ###
    uc.mem_protect(GLOBAL_VAR.SectionInfo[1][0], align(GLOBAL_VAR.SectionInfo[1][1]), UC_PROT_READ)
    GLOBAL_VAR.SectionInfo[1][2]=0x2
    ###          ###
    
    print("PID : ",os.getpid())
    try:
        uc.emu_start(GLOBAL_VAR.ImageBaseStart + EP, GLOBAL_VAR.ImageBaseEnd)
    except UcError as e:
        print(f"[ERROR]: {e}")
        BobLog.info("Find OEP : %s" % hex(uc.reg_read(UC_X86_REG_RIP)))
        #BobLog.debug("DEBUGING")
  
    end = datetime.now()
    print(f"[{end}] Emulation done...")
    print(f"Runtime: [{end-start}]")


def P_DLL_Function():
    for key in DLL_SETTING.DllFuncs:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.DllFuncs[key])))
    

def P_INV_DLL_Function():
    for key in DLL_SETTING.InverseDllFuncs:
        print("key : {0}, value : {1}".format(hex(key),DLL_SETTING.InverseDllFuncs[key]))

def P_LOADED_DLL():
    for key in DLL_SETTING.LoadedDll:
        print("key : {0}, value : {1}".format(key,hex(DLL_SETTING.LoadedDll[key])))